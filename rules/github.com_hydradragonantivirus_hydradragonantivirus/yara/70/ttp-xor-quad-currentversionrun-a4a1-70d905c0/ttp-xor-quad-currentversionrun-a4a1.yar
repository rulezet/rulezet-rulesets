rule TTP_XOR_QUAD_CurrentVersionRun_a4a1 {
  strings:
    $key_a4a1 = { f7 ce [2] d3 c0 [2] f8 ec [2] d6 ce [2] c2 d5 [2] cd cf [2] d3 d2 [2] d1 d3 [2] ca d5 [2] d6 d2 [2] ca fd }

  condition:
    any of them
}