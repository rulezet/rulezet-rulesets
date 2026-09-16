rule TTP_XOR_QUAD_CurrentVersionRun_b4d2 {
  strings:
    $key_b4d2 = { e7 bd [2] c3 b3 [2] e8 9f [2] c6 bd [2] d2 a6 [2] dd bc [2] c3 a1 [2] c1 a0 [2] da a6 [2] c6 a1 [2] da 8e }

  condition:
    any of them
}