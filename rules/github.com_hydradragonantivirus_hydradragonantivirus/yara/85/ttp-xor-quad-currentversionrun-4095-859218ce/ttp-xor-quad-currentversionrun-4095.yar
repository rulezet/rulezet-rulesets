rule TTP_XOR_QUAD_CurrentVersionRun_4095 {
  strings:
    $key_4095 = { 13 fa [2] 37 f4 [2] 1c d8 [2] 32 fa [2] 26 e1 [2] 29 fb [2] 37 e6 [2] 35 e7 [2] 2e e1 [2] 32 e6 [2] 2e c9 }

  condition:
    any of them
}