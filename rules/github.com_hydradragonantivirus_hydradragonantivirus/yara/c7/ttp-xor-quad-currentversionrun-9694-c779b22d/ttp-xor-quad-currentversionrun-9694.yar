rule TTP_XOR_QUAD_CurrentVersionRun_9694 {
  strings:
    $key_9694 = { c5 fb [2] e1 f5 [2] ca d9 [2] e4 fb [2] f0 e0 [2] ff fa [2] e1 e7 [2] e3 e6 [2] f8 e0 [2] e4 e7 [2] f8 c8 }

  condition:
    any of them
}