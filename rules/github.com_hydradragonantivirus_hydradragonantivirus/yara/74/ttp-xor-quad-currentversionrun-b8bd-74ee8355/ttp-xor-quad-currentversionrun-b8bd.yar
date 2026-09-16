rule TTP_XOR_QUAD_CurrentVersionRun_b8bd {
  strings:
    $key_b8bd = { eb d2 [2] cf dc [2] e4 f0 [2] ca d2 [2] de c9 [2] d1 d3 [2] cf ce [2] cd cf [2] d6 c9 [2] ca ce [2] d6 e1 }

  condition:
    any of them
}