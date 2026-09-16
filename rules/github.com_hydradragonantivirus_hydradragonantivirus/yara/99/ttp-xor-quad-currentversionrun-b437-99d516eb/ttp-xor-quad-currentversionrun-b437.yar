rule TTP_XOR_QUAD_CurrentVersionRun_b437 {
  strings:
    $key_b437 = { e7 58 [2] c3 56 [2] e8 7a [2] c6 58 [2] d2 43 [2] dd 59 [2] c3 44 [2] c1 45 [2] da 43 [2] c6 44 [2] da 6b }

  condition:
    any of them
}