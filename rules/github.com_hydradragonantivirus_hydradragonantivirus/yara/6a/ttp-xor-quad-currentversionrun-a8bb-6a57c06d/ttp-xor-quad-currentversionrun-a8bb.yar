rule TTP_XOR_QUAD_CurrentVersionRun_a8bb {
  strings:
    $key_a8bb = { fb d4 [2] df da [2] f4 f6 [2] da d4 [2] ce cf [2] c1 d5 [2] df c8 [2] dd c9 [2] c6 cf [2] da c8 [2] c6 e7 }

  condition:
    any of them
}