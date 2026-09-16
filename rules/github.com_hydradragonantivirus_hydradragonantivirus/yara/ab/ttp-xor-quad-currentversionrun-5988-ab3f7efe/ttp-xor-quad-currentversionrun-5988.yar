rule TTP_XOR_QUAD_CurrentVersionRun_5988 {
  strings:
    $key_5988 = { 0a e7 [2] 2e e9 [2] 05 c5 [2] 2b e7 [2] 3f fc [2] 30 e6 [2] 2e fb [2] 2c fa [2] 37 fc [2] 2b fb [2] 37 d4 }

  condition:
    any of them
}