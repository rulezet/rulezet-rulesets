rule TTP_XOR_QUAD_CurrentVersionRun_848f {
  strings:
    $key_848f = { d7 e0 [2] f3 ee [2] d8 c2 [2] f6 e0 [2] e2 fb [2] ed e1 [2] f3 fc [2] f1 fd [2] ea fb [2] f6 fc [2] ea d3 }

  condition:
    any of them
}