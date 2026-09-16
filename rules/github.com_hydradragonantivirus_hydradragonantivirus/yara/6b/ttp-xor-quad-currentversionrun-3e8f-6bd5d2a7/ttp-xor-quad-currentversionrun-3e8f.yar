rule TTP_XOR_QUAD_CurrentVersionRun_3e8f {
  strings:
    $key_3e8f = { 6d e0 [2] 49 ee [2] 62 c2 [2] 4c e0 [2] 58 fb [2] 57 e1 [2] 49 fc [2] 4b fd [2] 50 fb [2] 4c fc [2] 50 d3 }

  condition:
    any of them
}