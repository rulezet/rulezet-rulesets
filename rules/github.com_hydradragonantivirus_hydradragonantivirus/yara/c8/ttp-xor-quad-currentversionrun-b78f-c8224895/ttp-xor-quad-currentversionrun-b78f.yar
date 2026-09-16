rule TTP_XOR_QUAD_CurrentVersionRun_b78f {
  strings:
    $key_b78f = { e4 e0 [2] c0 ee [2] eb c2 [2] c5 e0 [2] d1 fb [2] de e1 [2] c0 fc [2] c2 fd [2] d9 fb [2] c5 fc [2] d9 d3 }

  condition:
    any of them
}