rule TTP_XOR_QUAD_CurrentVersionRun_2294 {
  strings:
    $key_2294 = { 71 fb [2] 55 f5 [2] 7e d9 [2] 50 fb [2] 44 e0 [2] 4b fa [2] 55 e7 [2] 57 e6 [2] 4c e0 [2] 50 e7 [2] 4c c8 }

  condition:
    any of them
}