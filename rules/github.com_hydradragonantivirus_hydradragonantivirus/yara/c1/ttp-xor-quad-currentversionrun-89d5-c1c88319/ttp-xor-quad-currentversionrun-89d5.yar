rule TTP_XOR_QUAD_CurrentVersionRun_89d5 {
  strings:
    $key_89d5 = { da ba [2] fe b4 [2] d5 98 [2] fb ba [2] ef a1 [2] e0 bb [2] fe a6 [2] fc a7 [2] e7 a1 [2] fb a6 [2] e7 89 }

  condition:
    any of them
}