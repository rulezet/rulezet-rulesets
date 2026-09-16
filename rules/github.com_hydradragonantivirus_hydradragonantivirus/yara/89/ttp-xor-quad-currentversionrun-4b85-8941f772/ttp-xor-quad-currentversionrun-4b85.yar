rule TTP_XOR_QUAD_CurrentVersionRun_4b85 {
  strings:
    $key_4b85 = { 18 ea [2] 3c e4 [2] 17 c8 [2] 39 ea [2] 2d f1 [2] 22 eb [2] 3c f6 [2] 3e f7 [2] 25 f1 [2] 39 f6 [2] 25 d9 }

  condition:
    any of them
}