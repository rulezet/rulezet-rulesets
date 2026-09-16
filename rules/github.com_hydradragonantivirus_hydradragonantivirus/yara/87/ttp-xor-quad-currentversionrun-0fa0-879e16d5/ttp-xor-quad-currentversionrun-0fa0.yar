rule TTP_XOR_QUAD_CurrentVersionRun_0fa0 {
  strings:
    $key_0fa0 = { 5c cf [2] 78 c1 [2] 53 ed [2] 7d cf [2] 69 d4 [2] 66 ce [2] 78 d3 [2] 7a d2 [2] 61 d4 [2] 7d d3 [2] 61 fc }

  condition:
    any of them
}