rule TTP_XOR_QUAD_CurrentVersionRun_30a0 {
  strings:
    $key_30a0 = { 63 cf [2] 47 c1 [2] 6c ed [2] 42 cf [2] 56 d4 [2] 59 ce [2] 47 d3 [2] 45 d2 [2] 5e d4 [2] 42 d3 [2] 5e fc }

  condition:
    any of them
}