rule TTP_XOR_QUAD_CurrentVersionRun_aea0 {
  strings:
    $key_aea0 = { fd cf [2] d9 c1 [2] f2 ed [2] dc cf [2] c8 d4 [2] c7 ce [2] d9 d3 [2] db d2 [2] c0 d4 [2] dc d3 [2] c0 fc }

  condition:
    any of them
}