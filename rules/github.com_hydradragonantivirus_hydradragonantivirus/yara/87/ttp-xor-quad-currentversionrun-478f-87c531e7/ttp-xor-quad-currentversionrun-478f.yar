rule TTP_XOR_QUAD_CurrentVersionRun_478f {
  strings:
    $key_478f = { 14 e0 [2] 30 ee [2] 1b c2 [2] 35 e0 [2] 21 fb [2] 2e e1 [2] 30 fc [2] 32 fd [2] 29 fb [2] 35 fc [2] 29 d3 }

  condition:
    any of them
}