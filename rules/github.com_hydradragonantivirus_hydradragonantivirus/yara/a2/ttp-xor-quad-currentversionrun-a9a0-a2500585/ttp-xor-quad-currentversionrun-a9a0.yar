rule TTP_XOR_QUAD_CurrentVersionRun_a9a0 {
  strings:
    $key_a9a0 = { fa cf [2] de c1 [2] f5 ed [2] db cf [2] cf d4 [2] c0 ce [2] de d3 [2] dc d2 [2] c7 d4 [2] db d3 [2] c7 fc }

  condition:
    any of them
}