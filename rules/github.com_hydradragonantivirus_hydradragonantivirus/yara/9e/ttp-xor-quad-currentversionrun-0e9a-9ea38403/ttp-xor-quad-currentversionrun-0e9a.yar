rule TTP_XOR_QUAD_CurrentVersionRun_0e9a {
  strings:
    $key_0e9a = { 5d f5 [2] 79 fb [2] 52 d7 [2] 7c f5 [2] 68 ee [2] 67 f4 [2] 79 e9 [2] 7b e8 [2] 60 ee [2] 7c e9 [2] 60 c6 }

  condition:
    any of them
}