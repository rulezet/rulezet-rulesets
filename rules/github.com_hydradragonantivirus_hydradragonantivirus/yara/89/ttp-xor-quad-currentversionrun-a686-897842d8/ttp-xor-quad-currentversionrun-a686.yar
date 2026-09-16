rule TTP_XOR_QUAD_CurrentVersionRun_a686 {
  strings:
    $key_a686 = { f5 e9 [2] d1 e7 [2] fa cb [2] d4 e9 [2] c0 f2 [2] cf e8 [2] d1 f5 [2] d3 f4 [2] c8 f2 [2] d4 f5 [2] c8 da }

  condition:
    any of them
}