rule TTP_XOR_QUAD_CurrentVersionRun_8697 {
  strings:
    $key_8697 = { d5 f8 [2] f1 f6 [2] da da [2] f4 f8 [2] e0 e3 [2] ef f9 [2] f1 e4 [2] f3 e5 [2] e8 e3 [2] f4 e4 [2] e8 cb }

  condition:
    any of them
}