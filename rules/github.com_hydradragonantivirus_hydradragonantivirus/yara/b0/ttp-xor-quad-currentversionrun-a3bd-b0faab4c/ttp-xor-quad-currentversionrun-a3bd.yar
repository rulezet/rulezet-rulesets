rule TTP_XOR_QUAD_CurrentVersionRun_a3bd {
  strings:
    $key_a3bd = { f0 d2 [2] d4 dc [2] ff f0 [2] d1 d2 [2] c5 c9 [2] ca d3 [2] d4 ce [2] d6 cf [2] cd c9 [2] d1 ce [2] cd e1 }

  condition:
    any of them
}