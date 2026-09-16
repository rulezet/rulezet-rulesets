rule TTP_XOR_QUAD_CurrentVersionRun_7fa0 {
  strings:
    $key_7fa0 = { 2c cf [2] 08 c1 [2] 23 ed [2] 0d cf [2] 19 d4 [2] 16 ce [2] 08 d3 [2] 0a d2 [2] 11 d4 [2] 0d d3 [2] 11 fc }

  condition:
    any of them
}