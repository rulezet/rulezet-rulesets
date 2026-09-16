rule TTP_XOR_QUAD_CurrentVersionRun_a8a1 {
  strings:
    $key_a8a1 = { fb ce [2] df c0 [2] f4 ec [2] da ce [2] ce d5 [2] c1 cf [2] df d2 [2] dd d3 [2] c6 d5 [2] da d2 [2] c6 fd }

  condition:
    any of them
}