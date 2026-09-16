rule TTP_XOR_QUAD_CurrentVersionRun_6088 {
  strings:
    $key_6088 = { 33 e7 [2] 17 e9 [2] 3c c5 [2] 12 e7 [2] 06 fc [2] 09 e6 [2] 17 fb [2] 15 fa [2] 0e fc [2] 12 fb [2] 0e d4 }

  condition:
    any of them
}