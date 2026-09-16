rule TTP_XOR_QUAD_CurrentVersionRun_b7d4 {
  strings:
    $key_b7d4 = { e4 bb [2] c0 b5 [2] eb 99 [2] c5 bb [2] d1 a0 [2] de ba [2] c0 a7 [2] c2 a6 [2] d9 a0 [2] c5 a7 [2] d9 88 }

  condition:
    any of them
}