rule TTP_XOR_QUAD_CurrentVersionRun_87ae {
  strings:
    $key_87ae = { d4 c1 [2] f0 cf [2] db e3 [2] f5 c1 [2] e1 da [2] ee c0 [2] f0 dd [2] f2 dc [2] e9 da [2] f5 dd [2] e9 f2 }

  condition:
    any of them
}