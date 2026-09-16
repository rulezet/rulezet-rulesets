rule TTP_XOR_QUAD_CurrentVersionRun_57a0 {
  strings:
    $key_57a0 = { 04 cf [2] 20 c1 [2] 0b ed [2] 25 cf [2] 31 d4 [2] 3e ce [2] 20 d3 [2] 22 d2 [2] 39 d4 [2] 25 d3 [2] 39 fc }

  condition:
    any of them
}