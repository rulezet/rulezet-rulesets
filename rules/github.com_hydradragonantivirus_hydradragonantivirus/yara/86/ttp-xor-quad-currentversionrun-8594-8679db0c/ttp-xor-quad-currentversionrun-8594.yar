rule TTP_XOR_QUAD_CurrentVersionRun_8594 {
  strings:
    $key_8594 = { d6 fb [2] f2 f5 [2] d9 d9 [2] f7 fb [2] e3 e0 [2] ec fa [2] f2 e7 [2] f0 e6 [2] eb e0 [2] f7 e7 [2] eb c8 }

  condition:
    any of them
}