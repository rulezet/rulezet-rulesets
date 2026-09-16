rule TTP_XOR_QUAD_CurrentVersionRun_2ba0 {
  strings:
    $key_2ba0 = { 78 cf [2] 5c c1 [2] 77 ed [2] 59 cf [2] 4d d4 [2] 42 ce [2] 5c d3 [2] 5e d2 [2] 45 d4 [2] 59 d3 [2] 45 fc }

  condition:
    any of them
}