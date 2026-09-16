rule TTP_XOR_QUAD_CurrentVersionRun_abb5 {
  strings:
    $key_abb5 = { f8 da [2] dc d4 [2] f7 f8 [2] d9 da [2] cd c1 [2] c2 db [2] dc c6 [2] de c7 [2] c5 c1 [2] d9 c6 [2] c5 e9 }

  condition:
    any of them
}