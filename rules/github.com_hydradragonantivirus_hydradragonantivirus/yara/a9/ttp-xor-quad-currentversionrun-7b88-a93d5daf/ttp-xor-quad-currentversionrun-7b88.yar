rule TTP_XOR_QUAD_CurrentVersionRun_7b88 {
  strings:
    $key_7b88 = { 28 e7 [2] 0c e9 [2] 27 c5 [2] 09 e7 [2] 1d fc [2] 12 e6 [2] 0c fb [2] 0e fa [2] 15 fc [2] 09 fb [2] 15 d4 }

  condition:
    any of them
}