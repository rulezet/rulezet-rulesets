rule TTP_XOR_QUAD_CurrentVersionRun_9da5 {
  strings:
    $key_9da5 = { ce ca [2] ea c4 [2] c1 e8 [2] ef ca [2] fb d1 [2] f4 cb [2] ea d6 [2] e8 d7 [2] f3 d1 [2] ef d6 [2] f3 f9 }

  condition:
    any of them
}