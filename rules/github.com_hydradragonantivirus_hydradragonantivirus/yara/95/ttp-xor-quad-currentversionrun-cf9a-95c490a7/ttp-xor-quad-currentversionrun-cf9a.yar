rule TTP_XOR_QUAD_CurrentVersionRun_cf9a {
  strings:
    $key_cf9a = { 9c f5 [2] b8 fb [2] 93 d7 [2] bd f5 [2] a9 ee [2] a6 f4 [2] b8 e9 [2] ba e8 [2] a1 ee [2] bd e9 [2] a1 c6 }

  condition:
    any of them
}