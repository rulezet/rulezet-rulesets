rule TTP_XOR_QUAD_CurrentVersionRun_9da0 {
  strings:
    $key_9da0 = { ce cf [2] ea c1 [2] c1 ed [2] ef cf [2] fb d4 [2] f4 ce [2] ea d3 [2] e8 d2 [2] f3 d4 [2] ef d3 [2] f3 fc }

  condition:
    any of them
}