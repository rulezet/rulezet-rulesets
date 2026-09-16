rule TTP_XOR_QUAD_CurrentVersionRun_92a1 {
  strings:
    $key_92a1 = { c1 ce [2] e5 c0 [2] ce ec [2] e0 ce [2] f4 d5 [2] fb cf [2] e5 d2 [2] e7 d3 [2] fc d5 [2] e0 d2 [2] fc fd }

  condition:
    any of them
}