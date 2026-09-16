rule TTP_XOR_QUAD_CurrentVersionRun_b28f {
  strings:
    $key_b28f = { e1 e0 [2] c5 ee [2] ee c2 [2] c0 e0 [2] d4 fb [2] db e1 [2] c5 fc [2] c7 fd [2] dc fb [2] c0 fc [2] dc d3 }

  condition:
    any of them
}