rule TTP_XOR_QUAD_CurrentVersionRun_b775 {
  strings:
    $key_b775 = { e4 1a [2] c0 14 [2] eb 38 [2] c5 1a [2] d1 01 [2] de 1b [2] c0 06 [2] c2 07 [2] d9 01 [2] c5 06 [2] d9 29 }

  condition:
    any of them
}