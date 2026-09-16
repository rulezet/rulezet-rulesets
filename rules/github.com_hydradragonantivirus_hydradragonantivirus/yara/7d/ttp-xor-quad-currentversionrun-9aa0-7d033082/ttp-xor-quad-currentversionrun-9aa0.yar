rule TTP_XOR_QUAD_CurrentVersionRun_9aa0 {
  strings:
    $key_9aa0 = { c9 cf [2] ed c1 [2] c6 ed [2] e8 cf [2] fc d4 [2] f3 ce [2] ed d3 [2] ef d2 [2] f4 d4 [2] e8 d3 [2] f4 fc }

  condition:
    any of them
}