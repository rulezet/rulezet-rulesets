rule TTP_XOR_QUAD_CurrentVersionRun_76a0 {
  strings:
    $key_76a0 = { 25 cf [2] 01 c1 [2] 2a ed [2] 04 cf [2] 10 d4 [2] 1f ce [2] 01 d3 [2] 03 d2 [2] 18 d4 [2] 04 d3 [2] 18 fc }

  condition:
    any of them
}