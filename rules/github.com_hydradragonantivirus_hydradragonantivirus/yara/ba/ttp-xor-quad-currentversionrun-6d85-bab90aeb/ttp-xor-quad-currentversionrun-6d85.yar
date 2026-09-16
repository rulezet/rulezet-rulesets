rule TTP_XOR_QUAD_CurrentVersionRun_6d85 {
  strings:
    $key_6d85 = { 3e ea [2] 1a e4 [2] 31 c8 [2] 1f ea [2] 0b f1 [2] 04 eb [2] 1a f6 [2] 18 f7 [2] 03 f1 [2] 1f f6 [2] 03 d9 }

  condition:
    any of them
}