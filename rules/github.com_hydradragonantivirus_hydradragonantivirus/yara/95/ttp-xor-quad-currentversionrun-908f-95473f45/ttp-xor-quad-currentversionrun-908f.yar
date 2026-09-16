rule TTP_XOR_QUAD_CurrentVersionRun_908f {
  strings:
    $key_908f = { c3 e0 [2] e7 ee [2] cc c2 [2] e2 e0 [2] f6 fb [2] f9 e1 [2] e7 fc [2] e5 fd [2] fe fb [2] e2 fc [2] fe d3 }

  condition:
    any of them
}