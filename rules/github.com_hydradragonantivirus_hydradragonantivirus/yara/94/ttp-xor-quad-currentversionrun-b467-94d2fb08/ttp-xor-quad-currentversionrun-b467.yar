rule TTP_XOR_QUAD_CurrentVersionRun_b467 {
  strings:
    $key_b467 = { e7 08 [2] c3 06 [2] e8 2a [2] c6 08 [2] d2 13 [2] dd 09 [2] c3 14 [2] c1 15 [2] da 13 [2] c6 14 [2] da 3b }

  condition:
    any of them
}