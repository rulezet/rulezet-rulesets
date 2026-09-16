rule TTP_XOR_QUAD_CurrentVersionRun_65a0 {
  strings:
    $key_65a0 = { 36 cf [2] 12 c1 [2] 39 ed [2] 17 cf [2] 03 d4 [2] 0c ce [2] 12 d3 [2] 10 d2 [2] 0b d4 [2] 17 d3 [2] 0b fc }

  condition:
    any of them
}