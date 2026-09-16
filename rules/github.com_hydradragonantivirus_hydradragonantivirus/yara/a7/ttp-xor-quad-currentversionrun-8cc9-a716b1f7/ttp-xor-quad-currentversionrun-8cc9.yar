rule TTP_XOR_QUAD_CurrentVersionRun_8cc9 {
  strings:
    $key_8cc9 = { df a6 [2] fb a8 [2] d0 84 [2] fe a6 [2] ea bd [2] e5 a7 [2] fb ba [2] f9 bb [2] e2 bd [2] fe ba [2] e2 95 }

  condition:
    any of them
}