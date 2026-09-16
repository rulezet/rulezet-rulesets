rule TTP_XOR_QUAD_CurrentVersionRun_81a4 {
  strings:
    $key_81a4 = { d2 cb [2] f6 c5 [2] dd e9 [2] f3 cb [2] e7 d0 [2] e8 ca [2] f6 d7 [2] f4 d6 [2] ef d0 [2] f3 d7 [2] ef f8 }

  condition:
    any of them
}