rule TTP_XOR_QUAD_CurrentVersionRun_0ba0 {
  strings:
    $key_0ba0 = { 58 cf [2] 7c c1 [2] 57 ed [2] 79 cf [2] 6d d4 [2] 62 ce [2] 7c d3 [2] 7e d2 [2] 65 d4 [2] 79 d3 [2] 65 fc }

  condition:
    any of them
}