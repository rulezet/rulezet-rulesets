rule TTP_XOR_QUAD_CurrentVersionRun_9d94 {
  strings:
    $key_9d94 = { ce fb [2] ea f5 [2] c1 d9 [2] ef fb [2] fb e0 [2] f4 fa [2] ea e7 [2] e8 e6 [2] f3 e0 [2] ef e7 [2] f3 c8 }

  condition:
    any of them
}