rule TTP_XOR_QUAD_CurrentVersionRun_b4f5 {
  strings:
    $key_b4f5 = { e7 9a [2] c3 94 [2] e8 b8 [2] c6 9a [2] d2 81 [2] dd 9b [2] c3 86 [2] c1 87 [2] da 81 [2] c6 86 [2] da a9 }

  condition:
    any of them
}