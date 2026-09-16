rule TTP_XOR_QUAD_CurrentVersionRun_599a {
  strings:
    $key_599a = { 0a f5 [2] 2e fb [2] 05 d7 [2] 2b f5 [2] 3f ee [2] 30 f4 [2] 2e e9 [2] 2c e8 [2] 37 ee [2] 2b e9 [2] 37 c6 }

  condition:
    any of them
}