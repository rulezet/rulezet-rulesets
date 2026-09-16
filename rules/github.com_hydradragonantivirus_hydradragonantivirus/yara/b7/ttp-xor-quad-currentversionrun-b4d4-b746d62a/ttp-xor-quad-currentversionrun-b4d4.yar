rule TTP_XOR_QUAD_CurrentVersionRun_b4d4 {
  strings:
    $key_b4d4 = { e7 bb [2] c3 b5 [2] e8 99 [2] c6 bb [2] d2 a0 [2] dd ba [2] c3 a7 [2] c1 a6 [2] da a0 [2] c6 a7 [2] da 88 }

  condition:
    any of them
}