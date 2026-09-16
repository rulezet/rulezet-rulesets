rule TTP_XOR_QUAD_CurrentVersionRun_baaf {
  strings:
    $key_baaf = { e9 c0 [2] cd ce [2] e6 e2 [2] c8 c0 [2] dc db [2] d3 c1 [2] cd dc [2] cf dd [2] d4 db [2] c8 dc [2] d4 f3 }

  condition:
    any of them
}