rule TTP_XOR_QUAD_CurrentVersionRun_8ca1 {
  strings:
    $key_8ca1 = { df ce [2] fb c0 [2] d0 ec [2] fe ce [2] ea d5 [2] e5 cf [2] fb d2 [2] f9 d3 [2] e2 d5 [2] fe d2 [2] e2 fd }

  condition:
    any of them
}