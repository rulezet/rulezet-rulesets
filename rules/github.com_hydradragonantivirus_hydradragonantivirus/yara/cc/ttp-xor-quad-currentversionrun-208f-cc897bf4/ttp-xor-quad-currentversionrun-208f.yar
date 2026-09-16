rule TTP_XOR_QUAD_CurrentVersionRun_208f {
  strings:
    $key_208f = { 73 e0 [2] 57 ee [2] 7c c2 [2] 52 e0 [2] 46 fb [2] 49 e1 [2] 57 fc [2] 55 fd [2] 4e fb [2] 52 fc [2] 4e d3 }

  condition:
    any of them
}