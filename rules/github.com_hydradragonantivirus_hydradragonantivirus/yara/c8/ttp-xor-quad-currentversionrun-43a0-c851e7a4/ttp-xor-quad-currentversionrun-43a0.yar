rule TTP_XOR_QUAD_CurrentVersionRun_43a0 {
  strings:
    $key_43a0 = { 10 cf [2] 34 c1 [2] 1f ed [2] 31 cf [2] 25 d4 [2] 2a ce [2] 34 d3 [2] 36 d2 [2] 2d d4 [2] 31 d3 [2] 2d fc }

  condition:
    any of them
}