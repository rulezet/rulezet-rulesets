rule TTP_XOR_QUAD_CurrentVersionRun_3ba0 {
  strings:
    $key_3ba0 = { 68 cf [2] 4c c1 [2] 67 ed [2] 49 cf [2] 5d d4 [2] 52 ce [2] 4c d3 [2] 4e d2 [2] 55 d4 [2] 49 d3 [2] 55 fc }

  condition:
    any of them
}