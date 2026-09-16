rule TTP_XOR_QUAD_CurrentVersionRun_8ca6 {
  strings:
    $key_8ca6 = { df c9 [2] fb c7 [2] d0 eb [2] fe c9 [2] ea d2 [2] e5 c8 [2] fb d5 [2] f9 d4 [2] e2 d2 [2] fe d5 [2] e2 fa }

  condition:
    any of them
}