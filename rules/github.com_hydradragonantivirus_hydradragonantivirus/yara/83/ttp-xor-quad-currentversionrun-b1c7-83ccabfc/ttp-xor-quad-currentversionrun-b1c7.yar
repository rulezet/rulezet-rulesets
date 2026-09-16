rule TTP_XOR_QUAD_CurrentVersionRun_b1c7 {
  strings:
    $key_b1c7 = { e2 a8 [2] c6 a6 [2] ed 8a [2] c3 a8 [2] d7 b3 [2] d8 a9 [2] c6 b4 [2] c4 b5 [2] df b3 [2] c3 b4 [2] df 9b }

  condition:
    any of them
}