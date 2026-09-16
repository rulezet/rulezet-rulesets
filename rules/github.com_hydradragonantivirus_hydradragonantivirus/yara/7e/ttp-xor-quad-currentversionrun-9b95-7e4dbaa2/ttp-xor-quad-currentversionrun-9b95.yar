rule TTP_XOR_QUAD_CurrentVersionRun_9b95 {
  strings:
    $key_9b95 = { c8 fa [2] ec f4 [2] c7 d8 [2] e9 fa [2] fd e1 [2] f2 fb [2] ec e6 [2] ee e7 [2] f5 e1 [2] e9 e6 [2] f5 c9 }

  condition:
    any of them
}