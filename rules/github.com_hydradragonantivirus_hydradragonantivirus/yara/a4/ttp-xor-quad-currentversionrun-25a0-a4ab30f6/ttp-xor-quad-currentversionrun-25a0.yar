rule TTP_XOR_QUAD_CurrentVersionRun_25a0 {
  strings:
    $key_25a0 = { 76 cf [2] 52 c1 [2] 79 ed [2] 57 cf [2] 43 d4 [2] 4c ce [2] 52 d3 [2] 50 d2 [2] 4b d4 [2] 57 d3 [2] 4b fc }

  condition:
    any of them
}