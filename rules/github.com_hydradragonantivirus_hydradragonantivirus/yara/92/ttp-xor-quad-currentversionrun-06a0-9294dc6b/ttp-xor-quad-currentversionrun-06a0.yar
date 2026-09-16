rule TTP_XOR_QUAD_CurrentVersionRun_06a0 {
  strings:
    $key_06a0 = { 55 cf [2] 71 c1 [2] 5a ed [2] 74 cf [2] 60 d4 [2] 6f ce [2] 71 d3 [2] 73 d2 [2] 68 d4 [2] 74 d3 [2] 68 fc }

  condition:
    any of them
}