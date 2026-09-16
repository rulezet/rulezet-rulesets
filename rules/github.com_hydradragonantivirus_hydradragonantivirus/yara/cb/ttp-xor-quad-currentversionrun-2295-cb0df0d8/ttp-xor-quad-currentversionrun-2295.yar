rule TTP_XOR_QUAD_CurrentVersionRun_2295 {
  strings:
    $key_2295 = { 71 fa [2] 55 f4 [2] 7e d8 [2] 50 fa [2] 44 e1 [2] 4b fb [2] 55 e6 [2] 57 e7 [2] 4c e1 [2] 50 e6 [2] 4c c9 }

  condition:
    any of them
}