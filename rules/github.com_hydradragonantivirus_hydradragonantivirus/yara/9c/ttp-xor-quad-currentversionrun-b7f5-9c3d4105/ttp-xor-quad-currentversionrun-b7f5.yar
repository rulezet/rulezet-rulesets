rule TTP_XOR_QUAD_CurrentVersionRun_b7f5 {
  strings:
    $key_b7f5 = { e4 9a [2] c0 94 [2] eb b8 [2] c5 9a [2] d1 81 [2] de 9b [2] c0 86 [2] c2 87 [2] d9 81 [2] c5 86 [2] d9 a9 }

  condition:
    any of them
}