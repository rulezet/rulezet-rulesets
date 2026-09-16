rule TTP_XOR_QUAD_CurrentVersionRun_72a1 {
  strings:
    $key_72a1 = { 21 ce [2] 05 c0 [2] 2e ec [2] 00 ce [2] 14 d5 [2] 1b cf [2] 05 d2 [2] 07 d3 [2] 1c d5 [2] 00 d2 [2] 1c fd }

  condition:
    any of them
}