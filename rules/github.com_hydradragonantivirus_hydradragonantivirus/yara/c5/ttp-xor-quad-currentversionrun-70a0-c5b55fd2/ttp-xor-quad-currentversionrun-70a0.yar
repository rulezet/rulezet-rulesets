rule TTP_XOR_QUAD_CurrentVersionRun_70a0 {
  strings:
    $key_70a0 = { 23 cf [2] 07 c1 [2] 2c ed [2] 02 cf [2] 16 d4 [2] 19 ce [2] 07 d3 [2] 05 d2 [2] 1e d4 [2] 02 d3 [2] 1e fc }

  condition:
    any of them
}