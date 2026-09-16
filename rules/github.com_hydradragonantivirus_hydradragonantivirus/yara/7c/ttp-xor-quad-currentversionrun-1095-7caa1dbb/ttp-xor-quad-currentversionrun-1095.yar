rule TTP_XOR_QUAD_CurrentVersionRun_1095 {
  strings:
    $key_1095 = { 43 fa [2] 67 f4 [2] 4c d8 [2] 62 fa [2] 76 e1 [2] 79 fb [2] 67 e6 [2] 65 e7 [2] 7e e1 [2] 62 e6 [2] 7e c9 }

  condition:
    any of them
}