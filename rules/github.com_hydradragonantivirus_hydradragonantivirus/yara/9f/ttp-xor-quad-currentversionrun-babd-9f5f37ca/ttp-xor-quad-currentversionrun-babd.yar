rule TTP_XOR_QUAD_CurrentVersionRun_babd {
  strings:
    $key_babd = { e9 d2 [2] cd dc [2] e6 f0 [2] c8 d2 [2] dc c9 [2] d3 d3 [2] cd ce [2] cf cf [2] d4 c9 [2] c8 ce [2] d4 e1 }

  condition:
    any of them
}