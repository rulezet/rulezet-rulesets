rule TTP_XOR_QUAD_CurrentVersionRun_b7f4 {
  strings:
    $key_b7f4 = { e4 9b [2] c0 95 [2] eb b9 [2] c5 9b [2] d1 80 [2] de 9a [2] c0 87 [2] c2 86 [2] d9 80 [2] c5 87 [2] d9 a8 }

  condition:
    any of them
}