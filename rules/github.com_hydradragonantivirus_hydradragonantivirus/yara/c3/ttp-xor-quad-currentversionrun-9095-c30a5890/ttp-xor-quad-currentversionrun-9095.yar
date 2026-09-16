rule TTP_XOR_QUAD_CurrentVersionRun_9095 {
  strings:
    $key_9095 = { c3 fa [2] e7 f4 [2] cc d8 [2] e2 fa [2] f6 e1 [2] f9 fb [2] e7 e6 [2] e5 e7 [2] fe e1 [2] e2 e6 [2] fe c9 }

  condition:
    any of them
}