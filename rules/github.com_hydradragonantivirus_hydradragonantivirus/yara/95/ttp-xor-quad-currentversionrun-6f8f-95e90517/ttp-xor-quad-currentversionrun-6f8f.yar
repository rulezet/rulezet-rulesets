rule TTP_XOR_QUAD_CurrentVersionRun_6f8f {
  strings:
    $key_6f8f = { 3c e0 [2] 18 ee [2] 33 c2 [2] 1d e0 [2] 09 fb [2] 06 e1 [2] 18 fc [2] 1a fd [2] 01 fb [2] 1d fc [2] 01 d3 }

  condition:
    any of them
}