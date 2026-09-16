rule TTP_XOR_QUAD_CurrentVersionRun_b764 {
  strings:
    $key_b764 = { e4 0b [2] c0 05 [2] eb 29 [2] c5 0b [2] d1 10 [2] de 0a [2] c0 17 [2] c2 16 [2] d9 10 [2] c5 17 [2] d9 38 }

  condition:
    any of them
}