rule TTP_XOR_QUAD_CurrentVersionRun_8fbb {
  strings:
    $key_8fbb = { dc d4 [2] f8 da [2] d3 f6 [2] fd d4 [2] e9 cf [2] e6 d5 [2] f8 c8 [2] fa c9 [2] e1 cf [2] fd c8 [2] e1 e7 }

  condition:
    any of them
}