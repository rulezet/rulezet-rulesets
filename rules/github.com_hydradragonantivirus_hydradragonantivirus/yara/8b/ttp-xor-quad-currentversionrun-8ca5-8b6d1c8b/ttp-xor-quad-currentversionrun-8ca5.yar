rule TTP_XOR_QUAD_CurrentVersionRun_8ca5 {
  strings:
    $key_8ca5 = { df ca [2] fb c4 [2] d0 e8 [2] fe ca [2] ea d1 [2] e5 cb [2] fb d6 [2] f9 d7 [2] e2 d1 [2] fe d6 [2] e2 f9 }

  condition:
    any of them
}