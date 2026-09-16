rule TTP_XOR_QUAD_CurrentVersionRun_b737 {
  strings:
    $key_b737 = { e4 58 [2] c0 56 [2] eb 7a [2] c5 58 [2] d1 43 [2] de 59 [2] c0 44 [2] c2 45 [2] d9 43 [2] c5 44 [2] d9 6b }

  condition:
    any of them
}