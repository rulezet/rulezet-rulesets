rule TTP_XOR_QUAD_CurrentVersionRun_95ce {
  strings:
    $key_95ce = { c6 a1 [2] e2 af [2] c9 83 [2] e7 a1 [2] f3 ba [2] fc a0 [2] e2 bd [2] e0 bc [2] fb ba [2] e7 bd [2] fb 92 }

  condition:
    any of them
}