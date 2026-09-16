rule TTP_XOR_QUAD_CurrentVersionRun_3d85 {
  strings:
    $key_3d85 = { 6e ea [2] 4a e4 [2] 61 c8 [2] 4f ea [2] 5b f1 [2] 54 eb [2] 4a f6 [2] 48 f7 [2] 53 f1 [2] 4f f6 [2] 53 d9 }

  condition:
    any of them
}