rule TTP_XOR_QUAD_CurrentVersionRun_858f {
  strings:
    $key_858f = { d6 e0 [2] f2 ee [2] d9 c2 [2] f7 e0 [2] e3 fb [2] ec e1 [2] f2 fc [2] f0 fd [2] eb fb [2] f7 fc [2] eb d3 }

  condition:
    any of them
}