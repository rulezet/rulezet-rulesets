rule TTP_XOR_QUAD_CurrentVersionRun_7f8f {
  strings:
    $key_7f8f = { 2c e0 [2] 08 ee [2] 23 c2 [2] 0d e0 [2] 19 fb [2] 16 e1 [2] 08 fc [2] 0a fd [2] 11 fb [2] 0d fc [2] 11 d3 }

  condition:
    any of them
}