rule TTP_XOR_QUAD_CurrentVersionRun_a8d5 {
  strings:
    $key_a8d5 = { fb ba [2] df b4 [2] f4 98 [2] da ba [2] ce a1 [2] c1 bb [2] df a6 [2] dd a7 [2] c6 a1 [2] da a6 [2] c6 89 }

  condition:
    any of them
}