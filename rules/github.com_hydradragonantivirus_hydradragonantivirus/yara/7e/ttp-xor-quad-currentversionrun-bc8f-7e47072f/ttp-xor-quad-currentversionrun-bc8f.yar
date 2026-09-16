rule TTP_XOR_QUAD_CurrentVersionRun_bc8f {
  strings:
    $key_bc8f = { ef e0 [2] cb ee [2] e0 c2 [2] ce e0 [2] da fb [2] d5 e1 [2] cb fc [2] c9 fd [2] d2 fb [2] ce fc [2] d2 d3 }

  condition:
    any of them
}