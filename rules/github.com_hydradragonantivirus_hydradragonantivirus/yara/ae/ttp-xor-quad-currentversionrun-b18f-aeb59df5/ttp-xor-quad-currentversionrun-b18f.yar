rule TTP_XOR_QUAD_CurrentVersionRun_b18f {
  strings:
    $key_b18f = { e2 e0 [2] c6 ee [2] ed c2 [2] c3 e0 [2] d7 fb [2] d8 e1 [2] c6 fc [2] c4 fd [2] df fb [2] c3 fc [2] df d3 }

  condition:
    any of them
}