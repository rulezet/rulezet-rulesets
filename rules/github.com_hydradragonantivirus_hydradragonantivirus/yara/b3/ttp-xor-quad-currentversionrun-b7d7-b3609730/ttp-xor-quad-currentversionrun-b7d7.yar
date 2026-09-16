rule TTP_XOR_QUAD_CurrentVersionRun_b7d7 {
  strings:
    $key_b7d7 = { e4 b8 [2] c0 b6 [2] eb 9a [2] c5 b8 [2] d1 a3 [2] de b9 [2] c0 a4 [2] c2 a5 [2] d9 a3 [2] c5 a4 [2] d9 8b }

  condition:
    any of them
}