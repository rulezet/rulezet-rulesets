rule TTP_XOR_QUAD_CurrentVersionRun_b426 {
  strings:
    $key_b426 = { e7 49 [2] c3 47 [2] e8 6b [2] c6 49 [2] d2 52 [2] dd 48 [2] c3 55 [2] c1 54 [2] da 52 [2] c6 55 [2] da 7a }

  condition:
    any of them
}