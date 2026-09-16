rule TTP_XOR_QUAD_CurrentVersionRun_7988 {
  strings:
    $key_7988 = { 2a e7 [2] 0e e9 [2] 25 c5 [2] 0b e7 [2] 1f fc [2] 10 e6 [2] 0e fb [2] 0c fa [2] 17 fc [2] 0b fb [2] 17 d4 }

  condition:
    any of them
}