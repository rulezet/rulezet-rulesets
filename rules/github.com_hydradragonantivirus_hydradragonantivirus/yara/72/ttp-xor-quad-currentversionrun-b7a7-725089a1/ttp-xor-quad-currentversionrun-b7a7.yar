rule TTP_XOR_QUAD_CurrentVersionRun_b7a7 {
  strings:
    $key_b7a7 = { e4 c8 [2] c0 c6 [2] eb ea [2] c5 c8 [2] d1 d3 [2] de c9 [2] c0 d4 [2] c2 d5 [2] d9 d3 [2] c5 d4 [2] d9 fb }

  condition:
    any of them
}