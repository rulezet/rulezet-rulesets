rule TTP_XOR_QUAD_CurrentVersionRun_81bd {
  strings:
    $key_81bd = { d2 d2 [2] f6 dc [2] dd f0 [2] f3 d2 [2] e7 c9 [2] e8 d3 [2] f6 ce [2] f4 cf [2] ef c9 [2] f3 ce [2] ef e1 }

  condition:
    any of them
}