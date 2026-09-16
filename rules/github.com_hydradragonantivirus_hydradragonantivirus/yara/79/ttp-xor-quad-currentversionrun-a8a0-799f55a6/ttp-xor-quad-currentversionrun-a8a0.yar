rule TTP_XOR_QUAD_CurrentVersionRun_a8a0 {
  strings:
    $key_a8a0 = { fb cf [2] df c1 [2] f4 ed [2] da cf [2] ce d4 [2] c1 ce [2] df d3 [2] dd d2 [2] c6 d4 [2] da d3 [2] c6 fc }

  condition:
    any of them
}