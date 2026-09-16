rule TTP_XOR_QUAD_CurrentVersionRun_5d85 {
  strings:
    $key_5d85 = { 0e ea [2] 2a e4 [2] 01 c8 [2] 2f ea [2] 3b f1 [2] 34 eb [2] 2a f6 [2] 28 f7 [2] 33 f1 [2] 2f f6 [2] 33 d9 }

  condition:
    any of them
}