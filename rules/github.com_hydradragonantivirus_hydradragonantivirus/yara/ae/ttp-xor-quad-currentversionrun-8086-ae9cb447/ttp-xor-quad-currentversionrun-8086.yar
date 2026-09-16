rule TTP_XOR_QUAD_CurrentVersionRun_8086 {
  strings:
    $key_8086 = { d3 e9 [2] f7 e7 [2] dc cb [2] f2 e9 [2] e6 f2 [2] e9 e8 [2] f7 f5 [2] f5 f4 [2] ee f2 [2] f2 f5 [2] ee da }

  condition:
    any of them
}