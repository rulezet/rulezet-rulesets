rule TTP_XOR_QUAD_CurrentVersionRun_8788 {
  strings:
    $key_8788 = { d4 e7 [2] f0 e9 [2] db c5 [2] f5 e7 [2] e1 fc [2] ee e6 [2] f0 fb [2] f2 fa [2] e9 fc [2] f5 fb [2] e9 d4 }

  condition:
    any of them
}