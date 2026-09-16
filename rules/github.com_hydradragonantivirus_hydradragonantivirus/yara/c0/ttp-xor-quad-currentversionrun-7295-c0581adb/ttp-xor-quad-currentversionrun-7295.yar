rule TTP_XOR_QUAD_CurrentVersionRun_7295 {
  strings:
    $key_7295 = { 21 fa [2] 05 f4 [2] 2e d8 [2] 00 fa [2] 14 e1 [2] 1b fb [2] 05 e6 [2] 07 e7 [2] 1c e1 [2] 00 e6 [2] 1c c9 }

  condition:
    any of them
}