rule TTP_XOR_QUAD_CurrentVersionRun_b4f4 {
  strings:
    $key_b4f4 = { e7 9b [2] c3 95 [2] e8 b9 [2] c6 9b [2] d2 80 [2] dd 9a [2] c3 87 [2] c1 86 [2] da 80 [2] c6 87 [2] da a8 }

  condition:
    any of them
}