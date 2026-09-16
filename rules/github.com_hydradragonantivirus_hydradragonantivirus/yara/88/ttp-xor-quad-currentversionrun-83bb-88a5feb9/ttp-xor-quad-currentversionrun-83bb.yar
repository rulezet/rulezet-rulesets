rule TTP_XOR_QUAD_CurrentVersionRun_83bb {
  strings:
    $key_83bb = { d0 d4 [2] f4 da [2] df f6 [2] f1 d4 [2] e5 cf [2] ea d5 [2] f4 c8 [2] f6 c9 [2] ed cf [2] f1 c8 [2] ed e7 }

  condition:
    any of them
}