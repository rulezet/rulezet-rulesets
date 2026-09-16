rule TTP_XOR_QUAD_CurrentVersionRun_b4aa {
  strings:
    $key_b4aa = { e7 c5 [2] c3 cb [2] e8 e7 [2] c6 c5 [2] d2 de [2] dd c4 [2] c3 d9 [2] c1 d8 [2] da de [2] c6 d9 [2] da f6 }

  condition:
    any of them
}