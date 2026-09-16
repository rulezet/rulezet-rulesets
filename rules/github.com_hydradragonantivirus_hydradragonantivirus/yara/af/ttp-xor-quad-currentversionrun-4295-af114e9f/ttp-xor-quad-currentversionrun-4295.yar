rule TTP_XOR_QUAD_CurrentVersionRun_4295 {
  strings:
    $key_4295 = { 11 fa [2] 35 f4 [2] 1e d8 [2] 30 fa [2] 24 e1 [2] 2b fb [2] 35 e6 [2] 37 e7 [2] 2c e1 [2] 30 e6 [2] 2c c9 }

  condition:
    any of them
}