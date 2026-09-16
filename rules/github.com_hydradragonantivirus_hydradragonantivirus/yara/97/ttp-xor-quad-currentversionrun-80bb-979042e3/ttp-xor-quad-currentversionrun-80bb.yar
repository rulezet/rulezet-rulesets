rule TTP_XOR_QUAD_CurrentVersionRun_80bb {
  strings:
    $key_80bb = { d3 d4 [2] f7 da [2] dc f6 [2] f2 d4 [2] e6 cf [2] e9 d5 [2] f7 c8 [2] f5 c9 [2] ee cf [2] f2 c8 [2] ee e7 }

  condition:
    any of them
}