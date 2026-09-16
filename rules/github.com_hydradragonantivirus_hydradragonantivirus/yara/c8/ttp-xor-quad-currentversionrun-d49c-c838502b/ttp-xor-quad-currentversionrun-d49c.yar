rule TTP_XOR_QUAD_CurrentVersionRun_d49c {
  strings:
    $key_d49c = { 87 f3 [2] a3 fd [2] 88 d1 [2] a6 f3 [2] b2 e8 [2] bd f2 [2] a3 ef [2] a1 ee [2] ba e8 [2] a6 ef [2] ba c0 }

  condition:
    any of them
}