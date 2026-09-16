rule TTP_XOR_QUAD_CurrentVersionRun_9595 {
  strings:
    $key_9595 = { c6 fa [2] e2 f4 [2] c9 d8 [2] e7 fa [2] f3 e1 [2] fc fb [2] e2 e6 [2] e0 e7 [2] fb e1 [2] e7 e6 [2] fb c9 }

  condition:
    any of them
}