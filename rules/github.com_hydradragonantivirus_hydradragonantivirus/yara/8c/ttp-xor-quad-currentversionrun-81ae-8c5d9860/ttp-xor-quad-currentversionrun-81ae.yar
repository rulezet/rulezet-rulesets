rule TTP_XOR_QUAD_CurrentVersionRun_81ae {
  strings:
    $key_81ae = { d2 c1 [2] f6 cf [2] dd e3 [2] f3 c1 [2] e7 da [2] e8 c0 [2] f6 dd [2] f4 dc [2] ef da [2] f3 dd [2] ef f2 }

  condition:
    any of them
}