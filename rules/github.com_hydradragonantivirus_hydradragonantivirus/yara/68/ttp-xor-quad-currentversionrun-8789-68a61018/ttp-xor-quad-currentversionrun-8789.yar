rule TTP_XOR_QUAD_CurrentVersionRun_8789 {
  strings:
    $key_8789 = { d4 e6 [2] f0 e8 [2] db c4 [2] f5 e6 [2] e1 fd [2] ee e7 [2] f0 fa [2] f2 fb [2] e9 fd [2] f5 fa [2] e9 d5 }

  condition:
    any of them
}