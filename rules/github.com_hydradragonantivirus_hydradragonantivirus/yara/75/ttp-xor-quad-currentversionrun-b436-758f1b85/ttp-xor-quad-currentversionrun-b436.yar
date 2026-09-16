rule TTP_XOR_QUAD_CurrentVersionRun_b436 {
  strings:
    $key_b436 = { e7 59 [2] c3 57 [2] e8 7b [2] c6 59 [2] d2 42 [2] dd 58 [2] c3 45 [2] c1 44 [2] da 42 [2] c6 45 [2] da 6a }

  condition:
    any of them
}