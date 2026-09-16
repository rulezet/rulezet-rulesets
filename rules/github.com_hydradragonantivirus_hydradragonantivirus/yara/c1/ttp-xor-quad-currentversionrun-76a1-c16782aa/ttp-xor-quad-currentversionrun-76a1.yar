rule TTP_XOR_QUAD_CurrentVersionRun_76a1 {
  strings:
    $key_76a1 = { 25 ce [2] 01 c0 [2] 2a ec [2] 04 ce [2] 10 d5 [2] 1f cf [2] 01 d2 [2] 03 d3 [2] 18 d5 [2] 04 d2 [2] 18 fd }

  condition:
    any of them
}