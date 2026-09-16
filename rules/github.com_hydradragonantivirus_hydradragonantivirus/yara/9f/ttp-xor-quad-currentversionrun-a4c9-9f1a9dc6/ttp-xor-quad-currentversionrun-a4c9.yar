rule TTP_XOR_QUAD_CurrentVersionRun_a4c9 {
  strings:
    $key_a4c9 = { f7 a6 [2] d3 a8 [2] f8 84 [2] d6 a6 [2] c2 bd [2] cd a7 [2] d3 ba [2] d1 bb [2] ca bd [2] d6 ba [2] ca 95 }

  condition:
    any of them
}