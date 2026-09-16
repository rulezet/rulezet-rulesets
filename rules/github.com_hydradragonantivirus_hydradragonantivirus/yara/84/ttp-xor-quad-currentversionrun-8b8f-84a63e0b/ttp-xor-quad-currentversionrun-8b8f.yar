rule TTP_XOR_QUAD_CurrentVersionRun_8b8f {
  strings:
    $key_8b8f = { d8 e0 [2] fc ee [2] d7 c2 [2] f9 e0 [2] ed fb [2] e2 e1 [2] fc fc [2] fe fd [2] e5 fb [2] f9 fc [2] e5 d3 }

  condition:
    any of them
}