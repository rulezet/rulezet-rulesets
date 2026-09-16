rule TTP_XOR_QUAD_CurrentVersionRun_9d88 {
  strings:
    $key_9d88 = { ce e7 [2] ea e9 [2] c1 c5 [2] ef e7 [2] fb fc [2] f4 e6 [2] ea fb [2] e8 fa [2] f3 fc [2] ef fb [2] f3 d4 }

  condition:
    any of them
}