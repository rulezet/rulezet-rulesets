rule TTP_XOR_QUAD_CurrentVersionRun_a194 {
  strings:
    $key_a194 = { f2 fb [2] d6 f5 [2] fd d9 [2] d3 fb [2] c7 e0 [2] c8 fa [2] d6 e7 [2] d4 e6 [2] cf e0 [2] d3 e7 [2] cf c8 }

  condition:
    any of them
}