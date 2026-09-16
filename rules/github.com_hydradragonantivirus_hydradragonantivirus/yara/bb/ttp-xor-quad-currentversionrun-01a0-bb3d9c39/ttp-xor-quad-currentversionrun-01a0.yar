rule TTP_XOR_QUAD_CurrentVersionRun_01a0 {
  strings:
    $key_01a0 = { 52 cf [2] 76 c1 [2] 5d ed [2] 73 cf [2] 67 d4 [2] 68 ce [2] 76 d3 [2] 74 d2 [2] 6f d4 [2] 73 d3 [2] 6f fc }

  condition:
    any of them
}