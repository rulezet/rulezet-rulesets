rule TTP_XOR_QUAD_CurrentVersionRun_a4c8 {
  strings:
    $key_a4c8 = { f7 a7 [2] d3 a9 [2] f8 85 [2] d6 a7 [2] c2 bc [2] cd a6 [2] d3 bb [2] d1 ba [2] ca bc [2] d6 bb [2] ca 94 }

  condition:
    any of them
}