rule TTP_XOR_QUAD_CurrentVersionRun_6488 {
  strings:
    $key_6488 = { 37 e7 [2] 13 e9 [2] 38 c5 [2] 16 e7 [2] 02 fc [2] 0d e6 [2] 13 fb [2] 11 fa [2] 0a fc [2] 16 fb [2] 0a d4 }

  condition:
    any of them
}