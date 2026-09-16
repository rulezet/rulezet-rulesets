rule TTP_XOR_QUAD_CurrentVersionRun_b39c {
  strings:
    $key_b39c = { e0 f3 [2] c4 fd [2] ef d1 [2] c1 f3 [2] d5 e8 [2] da f2 [2] c4 ef [2] c6 ee [2] dd e8 [2] c1 ef [2] dd c0 }

  condition:
    any of them
}