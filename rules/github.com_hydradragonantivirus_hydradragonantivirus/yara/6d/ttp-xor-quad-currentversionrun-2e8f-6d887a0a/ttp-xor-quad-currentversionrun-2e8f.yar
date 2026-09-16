rule TTP_XOR_QUAD_CurrentVersionRun_2e8f {
  strings:
    $key_2e8f = { 7d e0 [2] 59 ee [2] 72 c2 [2] 5c e0 [2] 48 fb [2] 47 e1 [2] 59 fc [2] 5b fd [2] 40 fb [2] 5c fc [2] 40 d3 }

  condition:
    any of them
}