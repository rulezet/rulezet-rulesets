rule TTP_XOR_QUAD_CurrentVersionRun_278f {
  strings:
    $key_278f = { 74 e0 [2] 50 ee [2] 7b c2 [2] 55 e0 [2] 41 fb [2] 4e e1 [2] 50 fc [2] 52 fd [2] 49 fb [2] 55 fc [2] 49 d3 }

  condition:
    any of them
}