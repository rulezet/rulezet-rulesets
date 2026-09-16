rule TTP_XOR_QUAD_CurrentVersionRun_8caa {
  strings:
    $key_8caa = { df c5 [2] fb cb [2] d0 e7 [2] fe c5 [2] ea de [2] e5 c4 [2] fb d9 [2] f9 d8 [2] e2 de [2] fe d9 [2] e2 f6 }

  condition:
    any of them
}