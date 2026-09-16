rule TTP_XOR_QUAD_CurrentVersionRun_95a0 {
  strings:
    $key_95a0 = { c6 cf [2] e2 c1 [2] c9 ed [2] e7 cf [2] f3 d4 [2] fc ce [2] e2 d3 [2] e0 d2 [2] fb d4 [2] e7 d3 [2] fb fc }

  condition:
    any of them
}