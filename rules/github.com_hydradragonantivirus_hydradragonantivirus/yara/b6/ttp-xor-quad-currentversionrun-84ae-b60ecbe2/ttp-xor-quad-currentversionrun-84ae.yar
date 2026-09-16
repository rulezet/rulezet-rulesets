rule TTP_XOR_QUAD_CurrentVersionRun_84ae {
  strings:
    $key_84ae = { d7 c1 [2] f3 cf [2] d8 e3 [2] f6 c1 [2] e2 da [2] ed c0 [2] f3 dd [2] f1 dc [2] ea da [2] f6 dd [2] ea f2 }

  condition:
    any of them
}