rule TTP_XOR_QUAD_CurrentVersionRun_8eaa {
  strings:
    $key_8eaa = { dd c5 [2] f9 cb [2] d2 e7 [2] fc c5 [2] e8 de [2] e7 c4 [2] f9 d9 [2] fb d8 [2] e0 de [2] fc d9 [2] e0 f6 }

  condition:
    any of them
}