rule TTP_XOR_QUAD_CurrentVersionRun_7c8f {
  strings:
    $key_7c8f = { 2f e0 [2] 0b ee [2] 20 c2 [2] 0e e0 [2] 1a fb [2] 15 e1 [2] 0b fc [2] 09 fd [2] 12 fb [2] 0e fc [2] 12 d3 }

  condition:
    any of them
}