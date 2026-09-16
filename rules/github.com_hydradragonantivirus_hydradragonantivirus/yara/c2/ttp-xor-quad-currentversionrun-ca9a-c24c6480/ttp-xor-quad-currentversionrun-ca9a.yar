rule TTP_XOR_QUAD_CurrentVersionRun_ca9a {
  strings:
    $key_ca9a = { 99 f5 [2] bd fb [2] 96 d7 [2] b8 f5 [2] ac ee [2] a3 f4 [2] bd e9 [2] bf e8 [2] a4 ee [2] b8 e9 [2] a4 c6 }

  condition:
    any of them
}