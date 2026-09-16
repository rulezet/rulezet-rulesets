rule TTP_XOR_QUAD_CurrentVersionRun_1ea0 {
  strings:
    $key_1ea0 = { 4d cf [2] 69 c1 [2] 42 ed [2] 6c cf [2] 78 d4 [2] 77 ce [2] 69 d3 [2] 6b d2 [2] 70 d4 [2] 6c d3 [2] 70 fc }

  condition:
    any of them
}