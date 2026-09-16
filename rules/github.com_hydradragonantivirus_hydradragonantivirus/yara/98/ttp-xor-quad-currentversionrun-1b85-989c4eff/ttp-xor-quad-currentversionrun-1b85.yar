rule TTP_XOR_QUAD_CurrentVersionRun_1b85 {
  strings:
    $key_1b85 = { 48 ea [2] 6c e4 [2] 47 c8 [2] 69 ea [2] 7d f1 [2] 72 eb [2] 6c f6 [2] 6e f7 [2] 75 f1 [2] 69 f6 [2] 75 d9 }

  condition:
    any of them
}