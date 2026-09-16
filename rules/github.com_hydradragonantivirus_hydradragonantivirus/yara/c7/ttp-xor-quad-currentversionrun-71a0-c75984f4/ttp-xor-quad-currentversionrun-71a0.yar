rule TTP_XOR_QUAD_CurrentVersionRun_71a0 {
  strings:
    $key_71a0 = { 22 cf [2] 06 c1 [2] 2d ed [2] 03 cf [2] 17 d4 [2] 18 ce [2] 06 d3 [2] 04 d2 [2] 1f d4 [2] 03 d3 [2] 1f fc }

  condition:
    any of them
}