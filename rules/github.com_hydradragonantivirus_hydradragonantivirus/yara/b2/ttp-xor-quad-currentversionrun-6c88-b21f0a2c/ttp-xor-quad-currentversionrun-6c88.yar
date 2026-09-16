rule TTP_XOR_QUAD_CurrentVersionRun_6c88 {
  strings:
    $key_6c88 = { 3f e7 [2] 1b e9 [2] 30 c5 [2] 1e e7 [2] 0a fc [2] 05 e6 [2] 1b fb [2] 19 fa [2] 02 fc [2] 1e fb [2] 02 d4 }

  condition:
    any of them
}