rule TTP_XOR_QUAD_CurrentVersionRun_bda1 {
  strings:
    $key_bda1 = { ee ce [2] ca c0 [2] e1 ec [2] cf ce [2] db d5 [2] d4 cf [2] ca d2 [2] c8 d3 [2] d3 d5 [2] cf d2 [2] d3 fd }

  condition:
    any of them
}