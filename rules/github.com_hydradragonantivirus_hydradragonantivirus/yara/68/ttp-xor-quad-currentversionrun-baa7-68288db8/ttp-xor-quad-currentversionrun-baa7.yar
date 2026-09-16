rule TTP_XOR_QUAD_CurrentVersionRun_baa7 {
  strings:
    $key_baa7 = { e9 c8 [2] cd c6 [2] e6 ea [2] c8 c8 [2] dc d3 [2] d3 c9 [2] cd d4 [2] cf d5 [2] d4 d3 [2] c8 d4 [2] d4 fb }

  condition:
    any of them
}