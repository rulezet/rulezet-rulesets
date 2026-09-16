rule TTP_XOR_QUAD_CurrentVersionRun_92d4 {
  strings:
    $key_92d4 = { c1 bb [2] e5 b5 [2] ce 99 [2] e0 bb [2] f4 a0 [2] fb ba [2] e5 a7 [2] e7 a6 [2] fc a0 [2] e0 a7 [2] fc 88 }

  condition:
    any of them
}