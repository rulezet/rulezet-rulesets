rule TTP_XOR_QUAD_CurrentVersionRun_8688 {
  strings:
    $key_8688 = { d5 e7 [2] f1 e9 [2] da c5 [2] f4 e7 [2] e0 fc [2] ef e6 [2] f1 fb [2] f3 fa [2] e8 fc [2] f4 fb [2] e8 d4 }

  condition:
    any of them
}