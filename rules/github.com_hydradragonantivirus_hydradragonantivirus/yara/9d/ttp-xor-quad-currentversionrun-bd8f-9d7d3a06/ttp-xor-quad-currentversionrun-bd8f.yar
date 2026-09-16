rule TTP_XOR_QUAD_CurrentVersionRun_bd8f {
  strings:
    $key_bd8f = { ee e0 [2] ca ee [2] e1 c2 [2] cf e0 [2] db fb [2] d4 e1 [2] ca fc [2] c8 fd [2] d3 fb [2] cf fc [2] d3 d3 }

  condition:
    any of them
}