rule TTP_XOR_QUAD_CurrentVersionRun_86aa {
  strings:
    $key_86aa = { d5 c5 [2] f1 cb [2] da e7 [2] f4 c5 [2] e0 de [2] ef c4 [2] f1 d9 [2] f3 d8 [2] e8 de [2] f4 d9 [2] e8 f6 }

  condition:
    any of them
}