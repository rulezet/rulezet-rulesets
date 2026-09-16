rule TTP_XOR_QUAD_CurrentVersionRun_b7a1 {
  strings:
    $key_b7a1 = { e4 ce [2] c0 c0 [2] eb ec [2] c5 ce [2] d1 d5 [2] de cf [2] c0 d2 [2] c2 d3 [2] d9 d5 [2] c5 d2 [2] d9 fd }

  condition:
    any of them
}