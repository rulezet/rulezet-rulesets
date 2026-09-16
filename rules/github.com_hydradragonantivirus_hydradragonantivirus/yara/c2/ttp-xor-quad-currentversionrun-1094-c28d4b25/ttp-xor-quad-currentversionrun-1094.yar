rule TTP_XOR_QUAD_CurrentVersionRun_1094 {
  strings:
    $key_1094 = { 43 fb [2] 67 f5 [2] 4c d9 [2] 62 fb [2] 76 e0 [2] 79 fa [2] 67 e7 [2] 65 e6 [2] 7e e0 [2] 62 e7 [2] 7e c8 }

  condition:
    any of them
}