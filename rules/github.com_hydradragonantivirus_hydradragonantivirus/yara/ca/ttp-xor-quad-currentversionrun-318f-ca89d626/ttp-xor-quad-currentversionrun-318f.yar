rule TTP_XOR_QUAD_CurrentVersionRun_318f {
  strings:
    $key_318f = { 62 e0 [2] 46 ee [2] 6d c2 [2] 43 e0 [2] 57 fb [2] 58 e1 [2] 46 fc [2] 44 fd [2] 5f fb [2] 43 fc [2] 5f d3 }

  condition:
    any of them
}