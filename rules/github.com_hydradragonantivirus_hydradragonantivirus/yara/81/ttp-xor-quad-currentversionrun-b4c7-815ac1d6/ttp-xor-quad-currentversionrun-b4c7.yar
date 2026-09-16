rule TTP_XOR_QUAD_CurrentVersionRun_b4c7 {
  strings:
    $key_b4c7 = { e7 a8 [2] c3 a6 [2] e8 8a [2] c6 a8 [2] d2 b3 [2] dd a9 [2] c3 b4 [2] c1 b5 [2] da b3 [2] c6 b4 [2] da 9b }

  condition:
    any of them
}