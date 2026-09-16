rule TTP_XOR_QUAD_CurrentVersionRun_00a0 {
  strings:
    $key_00a0 = { 53 cf [2] 77 c1 [2] 5c ed [2] 72 cf [2] 66 d4 [2] 69 ce [2] 77 d3 [2] 75 d2 [2] 6e d4 [2] 72 d3 [2] 6e fc }

  condition:
    any of them
}