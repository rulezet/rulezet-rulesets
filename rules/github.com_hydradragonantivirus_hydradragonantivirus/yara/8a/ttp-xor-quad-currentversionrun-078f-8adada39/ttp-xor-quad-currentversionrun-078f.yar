rule TTP_XOR_QUAD_CurrentVersionRun_078f {
  strings:
    $key_078f = { 54 e0 [2] 70 ee [2] 5b c2 [2] 75 e0 [2] 61 fb [2] 6e e1 [2] 70 fc [2] 72 fd [2] 69 fb [2] 75 fc [2] 69 d3 }

  condition:
    any of them
}