rule TTP_XOR_QUAD_CurrentVersionRun_aba7 {
  strings:
    $key_aba7 = { f8 c8 [2] dc c6 [2] f7 ea [2] d9 c8 [2] cd d3 [2] c2 c9 [2] dc d4 [2] de d5 [2] c5 d3 [2] d9 d4 [2] c5 fb }

  condition:
    any of them
}