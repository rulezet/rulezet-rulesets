rule TTP_XOR_QUAD_CurrentVersionRun_55a1 {
  strings:
    $key_55a1 = { 06 ce [2] 22 c0 [2] 09 ec [2] 27 ce [2] 33 d5 [2] 3c cf [2] 22 d2 [2] 20 d3 [2] 3b d5 [2] 27 d2 [2] 3b fd }

  condition:
    any of them
}