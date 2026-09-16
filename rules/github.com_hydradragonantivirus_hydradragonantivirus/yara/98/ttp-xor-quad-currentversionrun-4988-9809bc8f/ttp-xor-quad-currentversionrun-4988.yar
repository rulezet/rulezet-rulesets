rule TTP_XOR_QUAD_CurrentVersionRun_4988 {
  strings:
    $key_4988 = { 1a e7 [2] 3e e9 [2] 15 c5 [2] 3b e7 [2] 2f fc [2] 20 e6 [2] 3e fb [2] 3c fa [2] 27 fc [2] 3b fb [2] 27 d4 }

  condition:
    any of them
}