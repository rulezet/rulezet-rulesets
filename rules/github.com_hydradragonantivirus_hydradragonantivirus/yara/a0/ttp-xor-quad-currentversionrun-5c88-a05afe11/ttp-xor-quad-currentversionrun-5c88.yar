rule TTP_XOR_QUAD_CurrentVersionRun_5c88 {
  strings:
    $key_5c88 = { 0f e7 [2] 2b e9 [2] 00 c5 [2] 2e e7 [2] 3a fc [2] 35 e6 [2] 2b fb [2] 29 fa [2] 32 fc [2] 2e fb [2] 32 d4 }

  condition:
    any of them
}