rule TTP_XOR_QUAD_CurrentVersionRun_bd93 {
  strings:
    $key_bd93 = { ee fc [2] ca f2 [2] e1 de [2] cf fc [2] db e7 [2] d4 fd [2] ca e0 [2] c8 e1 [2] d3 e7 [2] cf e0 [2] d3 cf }

  condition:
    any of them
}