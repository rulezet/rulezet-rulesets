rule TTP_XOR_QUAD_CurrentVersionRun_83a0 {
  strings:
    $key_83a0 = { d0 cf [2] f4 c1 [2] df ed [2] f1 cf [2] e5 d4 [2] ea ce [2] f4 d3 [2] f6 d2 [2] ed d4 [2] f1 d3 [2] ed fc }

  condition:
    any of them
}