rule TTP_XOR_QUAD_CurrentVersionRun_15a0 {
  strings:
    $key_15a0 = { 46 cf [2] 62 c1 [2] 49 ed [2] 67 cf [2] 73 d4 [2] 7c ce [2] 62 d3 [2] 60 d2 [2] 7b d4 [2] 67 d3 [2] 7b fc }

  condition:
    any of them
}