rule TTP_XOR_QUAD_CurrentVersionRun_3e88 {
  strings:
    $key_3e88 = { 6d e7 [2] 49 e9 [2] 62 c5 [2] 4c e7 [2] 58 fc [2] 57 e6 [2] 49 fb [2] 4b fa [2] 50 fc [2] 4c fb [2] 50 d4 }

  condition:
    any of them
}