rule TTP_XOR_QUAD_CurrentVersionRun_b7d3 {
  strings:
    $key_b7d3 = { e4 bc [2] c0 b2 [2] eb 9e [2] c5 bc [2] d1 a7 [2] de bd [2] c0 a0 [2] c2 a1 [2] d9 a7 [2] c5 a0 [2] d9 8f }

  condition:
    any of them
}