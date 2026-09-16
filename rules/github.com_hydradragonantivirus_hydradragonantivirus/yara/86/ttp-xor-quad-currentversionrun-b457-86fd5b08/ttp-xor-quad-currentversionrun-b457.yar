rule TTP_XOR_QUAD_CurrentVersionRun_b457 {
  strings:
    $key_b457 = { e7 38 [2] c3 36 [2] e8 1a [2] c6 38 [2] d2 23 [2] dd 39 [2] c3 24 [2] c1 25 [2] da 23 [2] c6 24 [2] da 0b }

  condition:
    any of them
}