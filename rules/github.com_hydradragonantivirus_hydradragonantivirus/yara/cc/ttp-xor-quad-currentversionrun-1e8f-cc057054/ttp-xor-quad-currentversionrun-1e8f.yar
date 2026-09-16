rule TTP_XOR_QUAD_CurrentVersionRun_1e8f {
  strings:
    $key_1e8f = { 4d e0 [2] 69 ee [2] 42 c2 [2] 6c e0 [2] 78 fb [2] 77 e1 [2] 69 fc [2] 6b fd [2] 70 fb [2] 6c fc [2] 70 d3 }

  condition:
    any of them
}