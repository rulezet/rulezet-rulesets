rule TTP_XOR_QUAD_CurrentVersionRun_b4d1 {
  strings:
    $key_b4d1 = { e7 be [2] c3 b0 [2] e8 9c [2] c6 be [2] d2 a5 [2] dd bf [2] c3 a2 [2] c1 a3 [2] da a5 [2] c6 a2 [2] da 8d }

  condition:
    any of them
}