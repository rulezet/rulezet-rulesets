rule TTP_XOR_QUAD_CurrentVersionRun_5fa0 {
  strings:
    $key_5fa0 = { 0c cf [2] 28 c1 [2] 03 ed [2] 2d cf [2] 39 d4 [2] 36 ce [2] 28 d3 [2] 2a d2 [2] 31 d4 [2] 2d d3 [2] 31 fc }

  condition:
    any of them
}