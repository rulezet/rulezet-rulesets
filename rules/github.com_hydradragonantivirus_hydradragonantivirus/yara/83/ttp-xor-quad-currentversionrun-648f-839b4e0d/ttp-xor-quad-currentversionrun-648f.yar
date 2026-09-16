rule TTP_XOR_QUAD_CurrentVersionRun_648f {
  strings:
    $key_648f = { 37 e0 [2] 13 ee [2] 38 c2 [2] 16 e0 [2] 02 fb [2] 0d e1 [2] 13 fc [2] 11 fd [2] 0a fb [2] 16 fc [2] 0a d3 }

  condition:
    any of them
}