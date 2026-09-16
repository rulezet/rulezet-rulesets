rule TTP_XOR_QUAD_CurrentVersionRun_83bc {
  strings:
    $key_83bc = { d0 d3 [2] f4 dd [2] df f1 [2] f1 d3 [2] e5 c8 [2] ea d2 [2] f4 cf [2] f6 ce [2] ed c8 [2] f1 cf [2] ed e0 }

  condition:
    any of them
}