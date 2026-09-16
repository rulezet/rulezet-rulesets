rule TTP_XOR_QUAD_CurrentVersionRun_8a8f {
  strings:
    $key_8a8f = { d9 e0 [2] fd ee [2] d6 c2 [2] f8 e0 [2] ec fb [2] e3 e1 [2] fd fc [2] ff fd [2] e4 fb [2] f8 fc [2] e4 d3 }

  condition:
    any of them
}