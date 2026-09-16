rule TTP_XOR_QUAD_CurrentVersionRun_0f8f {
  strings:
    $key_0f8f = { 5c e0 [2] 78 ee [2] 53 c2 [2] 7d e0 [2] 69 fb [2] 66 e1 [2] 78 fc [2] 7a fd [2] 61 fb [2] 7d fc [2] 61 d3 }

  condition:
    any of them
}