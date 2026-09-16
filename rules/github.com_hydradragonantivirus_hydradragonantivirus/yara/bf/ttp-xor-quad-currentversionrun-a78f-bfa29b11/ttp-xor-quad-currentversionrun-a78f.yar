rule TTP_XOR_QUAD_CurrentVersionRun_a78f {
  strings:
    $key_a78f = { f4 e0 [2] d0 ee [2] fb c2 [2] d5 e0 [2] c1 fb [2] ce e1 [2] d0 fc [2] d2 fd [2] c9 fb [2] d5 fc [2] c9 d3 }

  condition:
    any of them
}