rule TTP_XOR_QUAD_CurrentVersionRun_a4a8 {
  strings:
    $key_a4a8 = { f7 c7 [2] d3 c9 [2] f8 e5 [2] d6 c7 [2] c2 dc [2] cd c6 [2] d3 db [2] d1 da [2] ca dc [2] d6 db [2] ca f4 }

  condition:
    any of them
}