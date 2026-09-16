rule TTP_XOR_QUAD_CurrentVersionRun_b1d6 {
  strings:
    $key_b1d6 = { e2 b9 [2] c6 b7 [2] ed 9b [2] c3 b9 [2] d7 a2 [2] d8 b8 [2] c6 a5 [2] c4 a4 [2] df a2 [2] c3 a5 [2] df 8a }

  condition:
    any of them
}