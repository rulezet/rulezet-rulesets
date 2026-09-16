rule TTP_XOR_QUAD_CurrentVersionRun_9d89 {
  strings:
    $key_9d89 = { ce e6 [2] ea e8 [2] c1 c4 [2] ef e6 [2] fb fd [2] f4 e7 [2] ea fa [2] e8 fb [2] f3 fd [2] ef fa [2] f3 d5 }

  condition:
    any of them
}