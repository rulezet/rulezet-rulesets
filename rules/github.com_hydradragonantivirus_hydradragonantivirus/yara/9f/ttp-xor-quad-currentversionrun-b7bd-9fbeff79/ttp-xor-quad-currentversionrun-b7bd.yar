rule TTP_XOR_QUAD_CurrentVersionRun_b7bd {
  strings:
    $key_b7bd = { e4 d2 [2] c0 dc [2] eb f0 [2] c5 d2 [2] d1 c9 [2] de d3 [2] c0 ce [2] c2 cf [2] d9 c9 [2] c5 ce [2] d9 e1 }

  condition:
    any of them
}