rule TTP_XOR_QUAD_CurrentVersionRun_bfbd {
  strings:
    $key_bfbd = { ec d2 [2] c8 dc [2] e3 f0 [2] cd d2 [2] d9 c9 [2] d6 d3 [2] c8 ce [2] ca cf [2] d1 c9 [2] cd ce [2] d1 e1 }

  condition:
    any of them
}