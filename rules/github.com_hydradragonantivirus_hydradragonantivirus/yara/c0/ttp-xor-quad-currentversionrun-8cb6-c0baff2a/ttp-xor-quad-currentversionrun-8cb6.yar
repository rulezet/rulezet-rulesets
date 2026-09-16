rule TTP_XOR_QUAD_CurrentVersionRun_8cb6 {
  strings:
    $key_8cb6 = { df d9 [2] fb d7 [2] d0 fb [2] fe d9 [2] ea c2 [2] e5 d8 [2] fb c5 [2] f9 c4 [2] e2 c2 [2] fe c5 [2] e2 ea }

  condition:
    any of them
}