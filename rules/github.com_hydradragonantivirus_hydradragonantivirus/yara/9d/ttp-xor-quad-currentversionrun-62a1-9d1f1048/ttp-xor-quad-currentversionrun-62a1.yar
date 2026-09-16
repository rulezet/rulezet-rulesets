rule TTP_XOR_QUAD_CurrentVersionRun_62a1 {
  strings:
    $key_62a1 = { 31 ce [2] 15 c0 [2] 3e ec [2] 10 ce [2] 04 d5 [2] 0b cf [2] 15 d2 [2] 17 d3 [2] 0c d5 [2] 10 d2 [2] 0c fd }

  condition:
    any of them
}