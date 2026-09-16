rule TTP_XOR_QUAD_CurrentVersionRun_9abd {
  strings:
    $key_9abd = { c9 d2 [2] ed dc [2] c6 f0 [2] e8 d2 [2] fc c9 [2] f3 d3 [2] ed ce [2] ef cf [2] f4 c9 [2] e8 ce [2] f4 e1 }

  condition:
    any of them
}