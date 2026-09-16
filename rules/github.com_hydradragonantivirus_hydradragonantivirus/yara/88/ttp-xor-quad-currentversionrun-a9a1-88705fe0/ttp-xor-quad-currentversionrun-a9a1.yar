rule TTP_XOR_QUAD_CurrentVersionRun_a9a1 {
  strings:
    $key_a9a1 = { fa ce [2] de c0 [2] f5 ec [2] db ce [2] cf d5 [2] c0 cf [2] de d2 [2] dc d3 [2] c7 d5 [2] db d2 [2] c7 fd }

  condition:
    any of them
}