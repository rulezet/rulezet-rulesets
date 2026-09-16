rule TTP_XOR_QUAD_CurrentVersionRun_b1d5 {
  strings:
    $key_b1d5 = { e2 ba [2] c6 b4 [2] ed 98 [2] c3 ba [2] d7 a1 [2] d8 bb [2] c6 a6 [2] c4 a7 [2] df a1 [2] c3 a6 [2] df 89 }

  condition:
    any of them
}