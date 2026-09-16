rule TTP_XOR_QUAD_CurrentVersionRun_4ea0 {
  strings:
    $key_4ea0 = { 1d cf [2] 39 c1 [2] 12 ed [2] 3c cf [2] 28 d4 [2] 27 ce [2] 39 d3 [2] 3b d2 [2] 20 d4 [2] 3c d3 [2] 20 fc }

  condition:
    any of them
}