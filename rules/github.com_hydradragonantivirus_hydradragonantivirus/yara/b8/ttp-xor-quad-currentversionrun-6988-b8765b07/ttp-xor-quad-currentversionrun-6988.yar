rule TTP_XOR_QUAD_CurrentVersionRun_6988 {
  strings:
    $key_6988 = { 3a e7 [2] 1e e9 [2] 35 c5 [2] 1b e7 [2] 0f fc [2] 00 e6 [2] 1e fb [2] 1c fa [2] 07 fc [2] 1b fb [2] 07 d4 }

  condition:
    any of them
}