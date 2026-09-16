rule TTP_XOR_QUAD_CurrentVersionRun_459a {
  strings:
    $key_459a = { 16 f5 [2] 32 fb [2] 19 d7 [2] 37 f5 [2] 23 ee [2] 2c f4 [2] 32 e9 [2] 30 e8 [2] 2b ee [2] 37 e9 [2] 2b c6 }

  condition:
    any of them
}