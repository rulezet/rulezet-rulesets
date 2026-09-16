rule TTP_XOR_QUAD_CurrentVersionRun_b744 {
  strings:
    $key_b744 = { e4 2b [2] c0 25 [2] eb 09 [2] c5 2b [2] d1 30 [2] de 2a [2] c0 37 [2] c2 36 [2] d9 30 [2] c5 37 [2] d9 18 }

  condition:
    any of them
}