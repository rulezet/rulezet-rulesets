rule TTP_XOR_QUAD_CurrentVersionRun_86a4 {
  strings:
    $key_86a4 = { d5 cb [2] f1 c5 [2] da e9 [2] f4 cb [2] e0 d0 [2] ef ca [2] f1 d7 [2] f3 d6 [2] e8 d0 [2] f4 d7 [2] e8 f8 }

  condition:
    any of them
}