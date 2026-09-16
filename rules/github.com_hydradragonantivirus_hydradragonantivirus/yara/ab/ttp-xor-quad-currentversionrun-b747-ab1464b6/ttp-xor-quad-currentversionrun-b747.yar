rule TTP_XOR_QUAD_CurrentVersionRun_b747 {
  strings:
    $key_b747 = { e4 28 [2] c0 26 [2] eb 0a [2] c5 28 [2] d1 33 [2] de 29 [2] c0 34 [2] c2 35 [2] d9 33 [2] c5 34 [2] d9 1b }

  condition:
    any of them
}