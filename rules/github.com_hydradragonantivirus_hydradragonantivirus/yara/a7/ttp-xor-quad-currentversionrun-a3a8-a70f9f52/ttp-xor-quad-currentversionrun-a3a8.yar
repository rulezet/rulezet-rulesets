rule TTP_XOR_QUAD_CurrentVersionRun_a3a8 {
  strings:
    $key_a3a8 = { f0 c7 [2] d4 c9 [2] ff e5 [2] d1 c7 [2] c5 dc [2] ca c6 [2] d4 db [2] d6 da [2] cd dc [2] d1 db [2] cd f4 }

  condition:
    any of them
}