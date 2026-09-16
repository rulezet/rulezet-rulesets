rule TTP_XOR_QUAD_CurrentVersionRun_898f {
  strings:
    $key_898f = { da e0 [2] fe ee [2] d5 c2 [2] fb e0 [2] ef fb [2] e0 e1 [2] fe fc [2] fc fd [2] e7 fb [2] fb fc [2] e7 d3 }

  condition:
    any of them
}