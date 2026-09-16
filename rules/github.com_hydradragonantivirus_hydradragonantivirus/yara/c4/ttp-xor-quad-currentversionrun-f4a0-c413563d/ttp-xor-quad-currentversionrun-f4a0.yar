rule TTP_XOR_QUAD_CurrentVersionRun_f4a0 {
  strings:
    $key_f4a0 = { a7 cf [2] 83 c1 [2] a8 ed [2] 86 cf [2] 92 d4 [2] 9d ce [2] 83 d3 [2] 81 d2 [2] 9a d4 [2] 86 d3 [2] 9a fc }

  condition:
    any of them
}