rule TTP_XOR_QUAD_CurrentVersionRun_9889 {
  strings:
    $key_9889 = { cb e6 [2] ef e8 [2] c4 c4 [2] ea e6 [2] fe fd [2] f1 e7 [2] ef fa [2] ed fb [2] f6 fd [2] ea fa [2] f6 d5 }

  condition:
    any of them
}