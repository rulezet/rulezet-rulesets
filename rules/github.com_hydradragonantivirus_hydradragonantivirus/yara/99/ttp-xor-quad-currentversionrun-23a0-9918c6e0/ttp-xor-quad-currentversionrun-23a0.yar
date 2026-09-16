rule TTP_XOR_QUAD_CurrentVersionRun_23a0 {
  strings:
    $key_23a0 = { 70 cf [2] 54 c1 [2] 7f ed [2] 51 cf [2] 45 d4 [2] 4a ce [2] 54 d3 [2] 56 d2 [2] 4d d4 [2] 51 d3 [2] 4d fc }

  condition:
    any of them
}