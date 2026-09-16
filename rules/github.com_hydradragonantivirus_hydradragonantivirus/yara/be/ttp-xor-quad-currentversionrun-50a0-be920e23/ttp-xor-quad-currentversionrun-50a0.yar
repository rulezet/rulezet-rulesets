rule TTP_XOR_QUAD_CurrentVersionRun_50a0 {
  strings:
    $key_50a0 = { 03 cf [2] 27 c1 [2] 0c ed [2] 22 cf [2] 36 d4 [2] 39 ce [2] 27 d3 [2] 25 d2 [2] 3e d4 [2] 22 d3 [2] 3e fc }

  condition:
    any of them
}