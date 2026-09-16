rule TTP_XOR_QUAD_CurrentVersionRun_a4bd {
  strings:
    $key_a4bd = { f7 d2 [2] d3 dc [2] f8 f0 [2] d6 d2 [2] c2 c9 [2] cd d3 [2] d3 ce [2] d1 cf [2] ca c9 [2] d6 ce [2] ca e1 }

  condition:
    any of them
}