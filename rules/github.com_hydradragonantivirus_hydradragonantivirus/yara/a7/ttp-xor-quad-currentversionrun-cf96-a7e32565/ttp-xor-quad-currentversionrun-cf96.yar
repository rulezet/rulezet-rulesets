rule TTP_XOR_QUAD_CurrentVersionRun_cf96 {
  strings:
    $key_cf96 = { 9c f9 [2] b8 f7 [2] 93 db [2] bd f9 [2] a9 e2 [2] a6 f8 [2] b8 e5 [2] ba e4 [2] a1 e2 [2] bd e5 [2] a1 ca }

  condition:
    any of them
}