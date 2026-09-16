rule TTP_XOR_QUAD_CurrentVersionRun_4e9a {
  strings:
    $key_4e9a = { 1d f5 [2] 39 fb [2] 12 d7 [2] 3c f5 [2] 28 ee [2] 27 f4 [2] 39 e9 [2] 3b e8 [2] 20 ee [2] 3c e9 [2] 20 c6 }

  condition:
    any of them
}