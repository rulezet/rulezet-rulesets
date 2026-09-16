rule TTP_XOR_QUAD_CurrentVersionRun_13a0 {
  strings:
    $key_13a0 = { 40 cf [2] 64 c1 [2] 4f ed [2] 61 cf [2] 75 d4 [2] 7a ce [2] 64 d3 [2] 66 d2 [2] 7d d4 [2] 61 d3 [2] 7d fc }

  condition:
    any of them
}