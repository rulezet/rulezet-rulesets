rule TTP_XOR_QUAD_CurrentVersionRun_3b85 {
  strings:
    $key_3b85 = { 68 ea [2] 4c e4 [2] 67 c8 [2] 49 ea [2] 5d f1 [2] 52 eb [2] 4c f6 [2] 4e f7 [2] 55 f1 [2] 49 f6 [2] 55 d9 }

  condition:
    any of them
}