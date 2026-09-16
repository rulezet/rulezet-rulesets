rule TTP_XOR_QUAD_CurrentVersionRun_8d8f {
  strings:
    $key_8d8f = { de e0 [2] fa ee [2] d1 c2 [2] ff e0 [2] eb fb [2] e4 e1 [2] fa fc [2] f8 fd [2] e3 fb [2] ff fc [2] e3 d3 }

  condition:
    any of them
}