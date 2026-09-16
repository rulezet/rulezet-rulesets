rule TTP_XOR_QUAD_CurrentVersionRun_8294 {
  strings:
    $key_8294 = { d1 fb [2] f5 f5 [2] de d9 [2] f0 fb [2] e4 e0 [2] eb fa [2] f5 e7 [2] f7 e6 [2] ec e0 [2] f0 e7 [2] ec c8 }

  condition:
    any of them
}