rule TTP_XOR_QUAD_CurrentVersionRun_958f {
  strings:
    $key_958f = { c6 e0 [2] e2 ee [2] c9 c2 [2] e7 e0 [2] f3 fb [2] fc e1 [2] e2 fc [2] e0 fd [2] fb fb [2] e7 fc [2] fb d3 }

  condition:
    any of them
}