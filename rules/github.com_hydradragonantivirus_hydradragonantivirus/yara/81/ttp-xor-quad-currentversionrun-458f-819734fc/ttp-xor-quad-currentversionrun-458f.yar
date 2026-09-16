rule TTP_XOR_QUAD_CurrentVersionRun_458f {
  strings:
    $key_458f = { 16 e0 [2] 32 ee [2] 19 c2 [2] 37 e0 [2] 23 fb [2] 2c e1 [2] 32 fc [2] 30 fd [2] 2b fb [2] 37 fc [2] 2b d3 }

  condition:
    any of them
}