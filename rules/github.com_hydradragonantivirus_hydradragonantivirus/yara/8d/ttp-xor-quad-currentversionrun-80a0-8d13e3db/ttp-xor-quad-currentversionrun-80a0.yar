rule TTP_XOR_QUAD_CurrentVersionRun_80a0 {
  strings:
    $key_80a0 = { d3 cf [2] f7 c1 [2] dc ed [2] f2 cf [2] e6 d4 [2] e9 ce [2] f7 d3 [2] f5 d2 [2] ee d4 [2] f2 d3 [2] ee fc }

  condition:
    any of them
}