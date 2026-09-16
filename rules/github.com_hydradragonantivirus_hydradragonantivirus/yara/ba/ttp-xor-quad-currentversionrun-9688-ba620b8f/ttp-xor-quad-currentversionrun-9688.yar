rule TTP_XOR_QUAD_CurrentVersionRun_9688 {
  strings:
    $key_9688 = { c5 e7 [2] e1 e9 [2] ca c5 [2] e4 e7 [2] f0 fc [2] ff e6 [2] e1 fb [2] e3 fa [2] f8 fc [2] e4 fb [2] f8 d4 }

  condition:
    any of them
}