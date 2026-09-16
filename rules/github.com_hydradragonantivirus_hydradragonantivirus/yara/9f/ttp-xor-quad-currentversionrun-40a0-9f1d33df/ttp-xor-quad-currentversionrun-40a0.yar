rule TTP_XOR_QUAD_CurrentVersionRun_40a0 {
  strings:
    $key_40a0 = { 13 cf [2] 37 c1 [2] 1c ed [2] 32 cf [2] 26 d4 [2] 29 ce [2] 37 d3 [2] 35 d2 [2] 2e d4 [2] 32 d3 [2] 2e fc }

  condition:
    any of them
}