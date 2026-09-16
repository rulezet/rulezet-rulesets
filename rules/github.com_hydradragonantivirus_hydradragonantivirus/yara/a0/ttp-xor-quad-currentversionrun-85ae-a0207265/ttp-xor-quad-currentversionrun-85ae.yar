rule TTP_XOR_QUAD_CurrentVersionRun_85ae {
  strings:
    $key_85ae = { d6 c1 [2] f2 cf [2] d9 e3 [2] f7 c1 [2] e3 da [2] ec c0 [2] f2 dd [2] f0 dc [2] eb da [2] f7 dd [2] eb f2 }

  condition:
    any of them
}