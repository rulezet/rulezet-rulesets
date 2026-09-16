rule TTP_XOR_QUAD_CurrentVersionRun_108f {
  strings:
    $key_108f = { 43 e0 [2] 67 ee [2] 4c c2 [2] 62 e0 [2] 76 fb [2] 79 e1 [2] 67 fc [2] 65 fd [2] 7e fb [2] 62 fc [2] 7e d3 }

  condition:
    any of them
}