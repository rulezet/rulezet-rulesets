rule TTP_XOR_QUAD_CurrentVersionRun_1d8f {
  strings:
    $key_1d8f = { 4e e0 [2] 6a ee [2] 41 c2 [2] 6f e0 [2] 7b fb [2] 74 e1 [2] 6a fc [2] 68 fd [2] 73 fb [2] 6f fc [2] 73 d3 }

  condition:
    any of them
}