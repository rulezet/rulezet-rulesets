rule TTP_XOR_QUAD_CurrentVersionRun_34a0 {
  strings:
    $key_34a0 = { 67 cf [2] 43 c1 [2] 68 ed [2] 46 cf [2] 52 d4 [2] 5d ce [2] 43 d3 [2] 41 d2 [2] 5a d4 [2] 46 d3 [2] 5a fc }

  condition:
    any of them
}