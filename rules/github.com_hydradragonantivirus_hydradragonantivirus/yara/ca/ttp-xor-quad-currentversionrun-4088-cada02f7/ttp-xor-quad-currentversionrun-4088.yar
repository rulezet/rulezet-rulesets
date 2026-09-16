rule TTP_XOR_QUAD_CurrentVersionRun_4088 {
  strings:
    $key_4088 = { 13 e7 [2] 37 e9 [2] 1c c5 [2] 32 e7 [2] 26 fc [2] 29 e6 [2] 37 fb [2] 35 fa [2] 2e fc [2] 32 fb [2] 2e d4 }

  condition:
    any of them
}