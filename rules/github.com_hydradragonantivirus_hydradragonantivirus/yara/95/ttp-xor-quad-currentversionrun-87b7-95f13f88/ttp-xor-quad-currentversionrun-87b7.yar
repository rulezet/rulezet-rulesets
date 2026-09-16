rule TTP_XOR_QUAD_CurrentVersionRun_87b7 {
  strings:
    $key_87b7 = { d4 d8 [2] f0 d6 [2] db fa [2] f5 d8 [2] e1 c3 [2] ee d9 [2] f0 c4 [2] f2 c5 [2] e9 c3 [2] f5 c4 [2] e9 eb }

  condition:
    any of them
}