rule TTP_XOR_QUAD_CurrentVersionRun_b434 {
  strings:
    $key_b434 = { e7 5b [2] c3 55 [2] e8 79 [2] c6 5b [2] d2 40 [2] dd 5a [2] c3 47 [2] c1 46 [2] da 40 [2] c6 47 [2] da 68 }

  condition:
    any of them
}