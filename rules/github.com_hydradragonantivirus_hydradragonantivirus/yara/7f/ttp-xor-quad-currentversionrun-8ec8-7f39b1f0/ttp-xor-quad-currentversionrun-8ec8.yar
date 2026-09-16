rule TTP_XOR_QUAD_CurrentVersionRun_8ec8 {
  strings:
    $key_8ec8 = { dd a7 [2] f9 a9 [2] d2 85 [2] fc a7 [2] e8 bc [2] e7 a6 [2] f9 bb [2] fb ba [2] e0 bc [2] fc bb [2] e0 94 }

  condition:
    any of them
}