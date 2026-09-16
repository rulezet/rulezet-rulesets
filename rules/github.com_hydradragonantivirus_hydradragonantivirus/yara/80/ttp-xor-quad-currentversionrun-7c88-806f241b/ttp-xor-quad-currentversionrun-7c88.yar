rule TTP_XOR_QUAD_CurrentVersionRun_7c88 {
  strings:
    $key_7c88 = { 2f e7 [2] 0b e9 [2] 20 c5 [2] 0e e7 [2] 1a fc [2] 15 e6 [2] 0b fb [2] 09 fa [2] 12 fc [2] 0e fb [2] 12 d4 }

  condition:
    any of them
}