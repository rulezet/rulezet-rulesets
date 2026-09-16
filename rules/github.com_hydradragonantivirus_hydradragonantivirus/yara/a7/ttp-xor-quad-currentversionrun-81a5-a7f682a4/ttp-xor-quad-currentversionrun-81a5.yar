rule TTP_XOR_QUAD_CurrentVersionRun_81a5 {
  strings:
    $key_81a5 = { d2 ca [2] f6 c4 [2] dd e8 [2] f3 ca [2] e7 d1 [2] e8 cb [2] f6 d6 [2] f4 d7 [2] ef d1 [2] f3 d6 [2] ef f9 }

  condition:
    any of them
}