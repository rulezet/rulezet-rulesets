rule TTP_XOR_QUAD_CurrentVersionRun_81bb {
  strings:
    $key_81bb = { d2 d4 [2] f6 da [2] dd f6 [2] f3 d4 [2] e7 cf [2] e8 d5 [2] f6 c8 [2] f4 c9 [2] ef cf [2] f3 c8 [2] ef e7 }

  condition:
    any of them
}