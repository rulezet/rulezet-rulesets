rule TTP_XOR_QUAD_CurrentVersionRun_bd89 {
  strings:
    $key_bd89 = { ee e6 [2] ca e8 [2] e1 c4 [2] cf e6 [2] db fd [2] d4 e7 [2] ca fa [2] c8 fb [2] d3 fd [2] cf fa [2] d3 d5 }

  condition:
    any of them
}