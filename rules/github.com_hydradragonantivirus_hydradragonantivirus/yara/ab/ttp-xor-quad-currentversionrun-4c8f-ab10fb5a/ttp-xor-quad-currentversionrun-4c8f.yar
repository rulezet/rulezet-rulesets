rule TTP_XOR_QUAD_CurrentVersionRun_4c8f {
  strings:
    $key_4c8f = { 1f e0 [2] 3b ee [2] 10 c2 [2] 3e e0 [2] 2a fb [2] 25 e1 [2] 3b fc [2] 39 fd [2] 22 fb [2] 3e fc [2] 22 d3 }

  condition:
    any of them
}