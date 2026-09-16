rule TTP_XOR_QUAD_CurrentVersionRun_8fbd {
  strings:
    $key_8fbd = { dc d2 [2] f8 dc [2] d3 f0 [2] fd d2 [2] e9 c9 [2] e6 d3 [2] f8 ce [2] fa cf [2] e1 c9 [2] fd ce [2] e1 e1 }

  condition:
    any of them
}