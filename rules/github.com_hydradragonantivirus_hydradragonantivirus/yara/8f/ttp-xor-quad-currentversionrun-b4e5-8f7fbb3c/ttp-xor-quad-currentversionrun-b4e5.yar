rule TTP_XOR_QUAD_CurrentVersionRun_b4e5 {
  strings:
    $key_b4e5 = { e7 8a [2] c3 84 [2] e8 a8 [2] c6 8a [2] d2 91 [2] dd 8b [2] c3 96 [2] c1 97 [2] da 91 [2] c6 96 [2] da b9 }

  condition:
    any of them
}