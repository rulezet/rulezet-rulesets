rule TTP_XOR_QUAD_CurrentVersionRun_80b7 {
  strings:
    $key_80b7 = { d3 d8 [2] f7 d6 [2] dc fa [2] f2 d8 [2] e6 c3 [2] e9 d9 [2] f7 c4 [2] f5 c5 [2] ee c3 [2] f2 c4 [2] ee eb }

  condition:
    any of them
}