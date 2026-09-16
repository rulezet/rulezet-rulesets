rule TTP_XOR_QUAD_CurrentVersionRun_a7bd {
  strings:
    $key_a7bd = { f4 d2 [2] d0 dc [2] fb f0 [2] d5 d2 [2] c1 c9 [2] ce d3 [2] d0 ce [2] d2 cf [2] c9 c9 [2] d5 ce [2] c9 e1 }

  condition:
    any of them
}