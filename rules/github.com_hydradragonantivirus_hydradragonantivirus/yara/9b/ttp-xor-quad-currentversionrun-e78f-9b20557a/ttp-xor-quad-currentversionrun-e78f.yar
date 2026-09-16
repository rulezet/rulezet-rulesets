rule TTP_XOR_QUAD_CurrentVersionRun_e78f {
  strings:
    $key_e78f = { b4 e0 [2] 90 ee [2] bb c2 [2] 95 e0 [2] 81 fb [2] 8e e1 [2] 90 fc [2] 92 fd [2] 89 fb [2] 95 fc [2] 89 d3 }

  condition:
    any of them
}