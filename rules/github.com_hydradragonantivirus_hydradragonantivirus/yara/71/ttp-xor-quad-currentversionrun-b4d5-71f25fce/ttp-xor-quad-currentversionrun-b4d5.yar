rule TTP_XOR_QUAD_CurrentVersionRun_b4d5 {
  strings:
    $key_b4d5 = { e7 ba [2] c3 b4 [2] e8 98 [2] c6 ba [2] d2 a1 [2] dd bb [2] c3 a6 [2] c1 a7 [2] da a1 [2] c6 a6 [2] da 89 }

  condition:
    any of them
}