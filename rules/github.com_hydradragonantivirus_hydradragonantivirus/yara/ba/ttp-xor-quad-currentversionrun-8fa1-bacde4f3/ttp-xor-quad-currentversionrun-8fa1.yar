rule TTP_XOR_QUAD_CurrentVersionRun_8fa1 {
  strings:
    $key_8fa1 = { dc ce [2] f8 c0 [2] d3 ec [2] fd ce [2] e9 d5 [2] e6 cf [2] f8 d2 [2] fa d3 [2] e1 d5 [2] fd d2 [2] e1 fd }

  condition:
    any of them
}