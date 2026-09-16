rule TTP_XOR_QUAD_CurrentVersionRun_b757 {
  strings:
    $key_b757 = { e4 38 [2] c0 36 [2] eb 1a [2] c5 38 [2] d1 23 [2] de 39 [2] c0 24 [2] c2 25 [2] d9 23 [2] c5 24 [2] d9 0b }

  condition:
    any of them
}