rule TTP_XOR_QUAD_CurrentVersionRun_9c95 {
  strings:
    $key_9c95 = { cf fa [2] eb f4 [2] c0 d8 [2] ee fa [2] fa e1 [2] f5 fb [2] eb e6 [2] e9 e7 [2] f2 e1 [2] ee e6 [2] f2 c9 }

  condition:
    any of them
}