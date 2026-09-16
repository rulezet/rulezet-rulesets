rule TTP_XOR_QUAD_CurrentVersionRun_92bd {
  strings:
    $key_92bd = { c1 d2 [2] e5 dc [2] ce f0 [2] e0 d2 [2] f4 c9 [2] fb d3 [2] e5 ce [2] e7 cf [2] fc c9 [2] e0 ce [2] fc e1 }

  condition:
    any of them
}