rule TTP_XOR_QUAD_CurrentVersionRun_4ba0 {
  strings:
    $key_4ba0 = { 18 cf [2] 3c c1 [2] 17 ed [2] 39 cf [2] 2d d4 [2] 22 ce [2] 3c d3 [2] 3e d2 [2] 25 d4 [2] 39 d3 [2] 25 fc }

  condition:
    any of them
}