rule TTP_XOR_QUAD_CurrentVersionRun_85bc {
  strings:
    $key_85bc = { d6 d3 [2] f2 dd [2] d9 f1 [2] f7 d3 [2] e3 c8 [2] ec d2 [2] f2 cf [2] f0 ce [2] eb c8 [2] f7 cf [2] eb e0 }

  condition:
    any of them
}