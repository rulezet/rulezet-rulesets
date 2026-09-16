rule TTP_XOR_QUAD_CurrentVersionRun_63a0 {
  strings:
    $key_63a0 = { 30 cf [2] 14 c1 [2] 3f ed [2] 11 cf [2] 05 d4 [2] 0a ce [2] 14 d3 [2] 16 d2 [2] 0d d4 [2] 11 d3 [2] 0d fc }

  condition:
    any of them
}