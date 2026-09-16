rule TTP_XOR_QUAD_CurrentVersionRun_5da0 {
  strings:
    $key_5da0 = { 0e cf [2] 2a c1 [2] 01 ed [2] 2f cf [2] 3b d4 [2] 34 ce [2] 2a d3 [2] 28 d2 [2] 33 d4 [2] 2f d3 [2] 33 fc }

  condition:
    any of them
}