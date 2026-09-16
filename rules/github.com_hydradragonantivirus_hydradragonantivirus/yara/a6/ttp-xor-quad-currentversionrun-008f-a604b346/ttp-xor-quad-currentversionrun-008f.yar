rule TTP_XOR_QUAD_CurrentVersionRun_008f {
  strings:
    $key_008f = { 53 e0 [2] 77 ee [2] 5c c2 [2] 72 e0 [2] 66 fb [2] 69 e1 [2] 77 fc [2] 75 fd [2] 6e fb [2] 72 fc [2] 6e d3 }

  condition:
    any of them
}