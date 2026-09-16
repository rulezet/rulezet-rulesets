rule TTP_XOR_QUAD_CurrentVersionRun_8ca7 {
  strings:
    $key_8ca7 = { df c8 [2] fb c6 [2] d0 ea [2] fe c8 [2] ea d3 [2] e5 c9 [2] fb d4 [2] f9 d5 [2] e2 d3 [2] fe d4 [2] e2 fb }

  condition:
    any of them
}