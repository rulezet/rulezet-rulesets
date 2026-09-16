rule TTP_XOR_QUAD_CurrentVersionRun_8cb8 {
  strings:
    $key_8cb8 = { df d7 [2] fb d9 [2] d0 f5 [2] fe d7 [2] ea cc [2] e5 d6 [2] fb cb [2] f9 ca [2] e2 cc [2] fe cb [2] e2 e4 }

  condition:
    any of them
}