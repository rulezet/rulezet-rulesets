rule TTP_XOR_QUAD_CurrentVersionRun_b475 {
  strings:
    $key_b475 = { e7 1a [2] c3 14 [2] e8 38 [2] c6 1a [2] d2 01 [2] dd 1b [2] c3 06 [2] c1 07 [2] da 01 [2] c6 06 [2] da 29 }

  condition:
    any of them
}