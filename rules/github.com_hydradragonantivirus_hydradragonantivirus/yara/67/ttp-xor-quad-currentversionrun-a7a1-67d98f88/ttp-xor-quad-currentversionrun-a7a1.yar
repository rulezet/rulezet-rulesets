rule TTP_XOR_QUAD_CurrentVersionRun_a7a1 {
  strings:
    $key_a7a1 = { f4 ce [2] d0 c0 [2] fb ec [2] d5 ce [2] c1 d5 [2] ce cf [2] d0 d2 [2] d2 d3 [2] c9 d5 [2] d5 d2 [2] c9 fd }

  condition:
    any of them
}