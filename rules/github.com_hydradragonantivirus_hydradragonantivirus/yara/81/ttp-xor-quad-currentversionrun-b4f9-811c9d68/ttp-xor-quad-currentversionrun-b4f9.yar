rule TTP_XOR_QUAD_CurrentVersionRun_b4f9 {
  strings:
    $key_b4f9 = { e7 96 [2] c3 98 [2] e8 b4 [2] c6 96 [2] d2 8d [2] dd 97 [2] c3 8a [2] c1 8b [2] da 8d [2] c6 8a [2] da a5 }

  condition:
    any of them
}