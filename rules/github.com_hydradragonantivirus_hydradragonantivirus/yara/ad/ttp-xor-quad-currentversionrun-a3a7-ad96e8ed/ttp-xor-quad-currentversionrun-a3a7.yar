rule TTP_XOR_QUAD_CurrentVersionRun_a3a7 {
  strings:
    $key_a3a7 = { f0 c8 [2] d4 c6 [2] ff ea [2] d1 c8 [2] c5 d3 [2] ca c9 [2] d4 d4 [2] d6 d5 [2] cd d3 [2] d1 d4 [2] cd fb }

  condition:
    any of them
}