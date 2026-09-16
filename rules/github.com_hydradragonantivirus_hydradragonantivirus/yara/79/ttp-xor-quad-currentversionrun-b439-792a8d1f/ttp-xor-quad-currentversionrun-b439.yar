rule TTP_XOR_QUAD_CurrentVersionRun_b439 {
  strings:
    $key_b439 = { e7 56 [2] c3 58 [2] e8 74 [2] c6 56 [2] d2 4d [2] dd 57 [2] c3 4a [2] c1 4b [2] da 4d [2] c6 4a [2] da 65 }

  condition:
    any of them
}