rule TTP_XOR_QUAD_CurrentVersionRun_a197 {
  strings:
    $key_a197 = { f2 f8 [2] d6 f6 [2] fd da [2] d3 f8 [2] c7 e3 [2] c8 f9 [2] d6 e4 [2] d4 e5 [2] cf e3 [2] d3 e4 [2] cf cb }

  condition:
    any of them
}