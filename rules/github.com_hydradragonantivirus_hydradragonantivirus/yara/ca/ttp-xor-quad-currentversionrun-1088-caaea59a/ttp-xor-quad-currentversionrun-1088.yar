rule TTP_XOR_QUAD_CurrentVersionRun_1088 {
  strings:
    $key_1088 = { 43 e7 [2] 67 e9 [2] 4c c5 [2] 62 e7 [2] 76 fc [2] 79 e6 [2] 67 fb [2] 65 fa [2] 7e fc [2] 62 fb [2] 7e d4 }

  condition:
    any of them
}