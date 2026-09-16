rule TTP_XOR_QUAD_CurrentVersionRun_a7a8 {
  strings:
    $key_a7a8 = { f4 c7 [2] d0 c9 [2] fb e5 [2] d5 c7 [2] c1 dc [2] ce c6 [2] d0 db [2] d2 da [2] c9 dc [2] d5 db [2] c9 f4 }

  condition:
    any of them
}