rule TTP_XOR_QUAD_CurrentVersionRun_928f {
  strings:
    $key_928f = { c1 e0 [2] e5 ee [2] ce c2 [2] e0 e0 [2] f4 fb [2] fb e1 [2] e5 fc [2] e7 fd [2] fc fb [2] e0 fc [2] fc d3 }

  condition:
    any of them
}