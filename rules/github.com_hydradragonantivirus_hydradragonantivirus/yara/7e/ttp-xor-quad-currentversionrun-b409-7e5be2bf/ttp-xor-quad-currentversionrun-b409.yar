rule TTP_XOR_QUAD_CurrentVersionRun_b409 {
  strings:
    $key_b409 = { e7 66 [2] c3 68 [2] e8 44 [2] c6 66 [2] d2 7d [2] dd 67 [2] c3 7a [2] c1 7b [2] da 7d [2] c6 7a [2] da 55 }

  condition:
    any of them
}