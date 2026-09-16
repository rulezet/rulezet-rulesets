rule TTP_XOR_QUAD_CurrentVersionRun_a481 {
  strings:
    $key_a481 = { f7 ee [2] d3 e0 [2] f8 cc [2] d6 ee [2] c2 f5 [2] cd ef [2] d3 f2 [2] d1 f3 [2] ca f5 [2] d6 f2 [2] ca dd }

  condition:
    any of them
}