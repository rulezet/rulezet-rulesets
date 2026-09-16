rule TTP_XOR_QUAD_CurrentVersionRun_a195 {
  strings:
    $key_a195 = { f2 fa [2] d6 f4 [2] fd d8 [2] d3 fa [2] c7 e1 [2] c8 fb [2] d6 e6 [2] d4 e7 [2] cf e1 [2] d3 e6 [2] cf c9 }

  condition:
    any of them
}