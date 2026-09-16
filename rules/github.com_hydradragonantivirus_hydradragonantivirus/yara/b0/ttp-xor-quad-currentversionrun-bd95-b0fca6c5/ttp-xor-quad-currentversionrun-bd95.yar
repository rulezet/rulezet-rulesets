rule TTP_XOR_QUAD_CurrentVersionRun_bd95 {
  strings:
    $key_bd95 = { ee fa [2] ca f4 [2] e1 d8 [2] cf fa [2] db e1 [2] d4 fb [2] ca e6 [2] c8 e7 [2] d3 e1 [2] cf e6 [2] d3 c9 }

  condition:
    any of them
}