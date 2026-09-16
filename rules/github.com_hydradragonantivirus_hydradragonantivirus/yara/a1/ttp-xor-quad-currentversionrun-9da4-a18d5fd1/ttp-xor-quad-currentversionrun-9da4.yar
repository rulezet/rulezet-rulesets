rule TTP_XOR_QUAD_CurrentVersionRun_9da4 {
  strings:
    $key_9da4 = { ce cb [2] ea c5 [2] c1 e9 [2] ef cb [2] fb d0 [2] f4 ca [2] ea d7 [2] e8 d6 [2] f3 d0 [2] ef d7 [2] f3 f8 }

  condition:
    any of them
}