rule TTP_XOR_QUAD_CurrentVersionRun_8794 {
  strings:
    $key_8794 = { d4 fb [2] f0 f5 [2] db d9 [2] f5 fb [2] e1 e0 [2] ee fa [2] f0 e7 [2] f2 e6 [2] e9 e0 [2] f5 e7 [2] e9 c8 }

  condition:
    any of them
}