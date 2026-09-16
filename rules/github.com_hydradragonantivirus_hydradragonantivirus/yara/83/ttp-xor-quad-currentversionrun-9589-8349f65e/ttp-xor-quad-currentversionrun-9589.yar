rule TTP_XOR_QUAD_CurrentVersionRun_9589 {
  strings:
    $key_9589 = { c6 e6 [2] e2 e8 [2] c9 c4 [2] e7 e6 [2] f3 fd [2] fc e7 [2] e2 fa [2] e0 fb [2] fb fd [2] e7 fa [2] fb d5 }

  condition:
    any of them
}