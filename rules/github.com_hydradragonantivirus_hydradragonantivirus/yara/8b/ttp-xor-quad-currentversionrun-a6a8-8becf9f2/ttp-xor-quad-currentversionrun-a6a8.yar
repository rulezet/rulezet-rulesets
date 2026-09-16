rule TTP_XOR_QUAD_CurrentVersionRun_a6a8 {
  strings:
    $key_a6a8 = { f5 c7 [2] d1 c9 [2] fa e5 [2] d4 c7 [2] c0 dc [2] cf c6 [2] d1 db [2] d3 da [2] c8 dc [2] d4 db [2] c8 f4 }

  condition:
    any of them
}