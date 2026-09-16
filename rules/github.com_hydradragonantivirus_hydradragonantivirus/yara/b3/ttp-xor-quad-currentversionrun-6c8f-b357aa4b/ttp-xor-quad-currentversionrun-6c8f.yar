rule TTP_XOR_QUAD_CurrentVersionRun_6c8f {
  strings:
    $key_6c8f = { 3f e0 [2] 1b ee [2] 30 c2 [2] 1e e0 [2] 0a fb [2] 05 e1 [2] 1b fc [2] 19 fd [2] 02 fb [2] 1e fc [2] 02 d3 }

  condition:
    any of them
}