rule TTP_XOR_QUAD_CurrentVersionRun_9d95 {
  strings:
    $key_9d95 = { ce fa [2] ea f4 [2] c1 d8 [2] ef fa [2] fb e1 [2] f4 fb [2] ea e6 [2] e8 e7 [2] f3 e1 [2] ef e6 [2] f3 c9 }

  condition:
    any of them
}