rule TTP_XOR_QUAD_CurrentVersionRun_4294 {
  strings:
    $key_4294 = { 11 fb [2] 35 f5 [2] 1e d9 [2] 30 fb [2] 24 e0 [2] 2b fa [2] 35 e7 [2] 37 e6 [2] 2c e0 [2] 30 e7 [2] 2c c8 }

  condition:
    any of them
}