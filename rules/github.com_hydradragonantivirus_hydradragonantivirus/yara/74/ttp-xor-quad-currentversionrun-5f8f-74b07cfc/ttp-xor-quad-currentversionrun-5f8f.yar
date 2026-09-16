rule TTP_XOR_QUAD_CurrentVersionRun_5f8f {
  strings:
    $key_5f8f = { 0c e0 [2] 28 ee [2] 03 c2 [2] 2d e0 [2] 39 fb [2] 36 e1 [2] 28 fc [2] 2a fd [2] 31 fb [2] 2d fc [2] 31 d3 }

  condition:
    any of them
}