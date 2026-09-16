rule TTP_XOR_QUAD_CurrentVersionRun_87a4 {
  strings:
    $key_87a4 = { d4 cb [2] f0 c5 [2] db e9 [2] f5 cb [2] e1 d0 [2] ee ca [2] f0 d7 [2] f2 d6 [2] e9 d0 [2] f5 d7 [2] e9 f8 }

  condition:
    any of them
}