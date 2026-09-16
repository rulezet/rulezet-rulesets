rule TTP_XOR_QUAD_CurrentVersionRun_e2a1 {
  strings:
    $key_e2a1 = { b1 ce [2] 95 c0 [2] be ec [2] 90 ce [2] 84 d5 [2] 8b cf [2] 95 d2 [2] 97 d3 [2] 8c d5 [2] 90 d2 [2] 8c fd }

  condition:
    any of them
}