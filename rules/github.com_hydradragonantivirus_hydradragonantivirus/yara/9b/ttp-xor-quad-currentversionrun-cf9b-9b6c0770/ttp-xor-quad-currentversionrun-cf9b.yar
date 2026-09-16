rule TTP_XOR_QUAD_CurrentVersionRun_cf9b {
  strings:
    $key_cf9b = { 9c f4 [2] b8 fa [2] 93 d6 [2] bd f4 [2] a9 ef [2] a6 f5 [2] b8 e8 [2] ba e9 [2] a1 ef [2] bd e8 [2] a1 c7 }

  condition:
    any of them
}