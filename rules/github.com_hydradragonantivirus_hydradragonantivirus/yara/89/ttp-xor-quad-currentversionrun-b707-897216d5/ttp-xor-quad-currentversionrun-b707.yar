rule TTP_XOR_QUAD_CurrentVersionRun_b707 {
  strings:
    $key_b707 = { e4 68 [2] c0 66 [2] eb 4a [2] c5 68 [2] d1 73 [2] de 69 [2] c0 74 [2] c2 75 [2] d9 73 [2] c5 74 [2] d9 5b }

  condition:
    any of them
}