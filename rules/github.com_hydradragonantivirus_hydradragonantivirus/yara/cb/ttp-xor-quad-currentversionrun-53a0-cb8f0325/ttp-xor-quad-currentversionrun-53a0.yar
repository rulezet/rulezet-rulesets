rule TTP_XOR_QUAD_CurrentVersionRun_53a0 {
  strings:
    $key_53a0 = { 00 cf [2] 24 c1 [2] 0f ed [2] 21 cf [2] 35 d4 [2] 3a ce [2] 24 d3 [2] 26 d2 [2] 3d d4 [2] 21 d3 [2] 3d fc }

  condition:
    any of them
}