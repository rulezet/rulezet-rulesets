rule TTP_XOR_QUAD_CurrentVersionRun_84a0 {
  strings:
    $key_84a0 = { d7 cf [2] f3 c1 [2] d8 ed [2] f6 cf [2] e2 d4 [2] ed ce [2] f3 d3 [2] f1 d2 [2] ea d4 [2] f6 d3 [2] ea fc }

  condition:
    any of them
}