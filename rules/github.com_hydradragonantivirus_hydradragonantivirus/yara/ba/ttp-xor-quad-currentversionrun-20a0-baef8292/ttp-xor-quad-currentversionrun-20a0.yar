rule TTP_XOR_QUAD_CurrentVersionRun_20a0 {
  strings:
    $key_20a0 = { 73 cf [2] 57 c1 [2] 7c ed [2] 52 cf [2] 46 d4 [2] 49 ce [2] 57 d3 [2] 55 d2 [2] 4e d4 [2] 52 d3 [2] 4e fc }

  condition:
    any of them
}