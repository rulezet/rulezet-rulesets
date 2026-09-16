rule TTP_XOR_QUAD_CurrentVersionRun_2088 {
  strings:
    $key_2088 = { 73 e7 [2] 57 e9 [2] 7c c5 [2] 52 e7 [2] 46 fc [2] 49 e6 [2] 57 fb [2] 55 fa [2] 4e fc [2] 52 fb [2] 4e d4 }

  condition:
    any of them
}