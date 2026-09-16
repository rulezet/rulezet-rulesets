rule TTP_XOR_QUAD_CurrentVersionRun_b1bd {
  strings:
    $key_b1bd = { e2 d2 [2] c6 dc [2] ed f0 [2] c3 d2 [2] d7 c9 [2] d8 d3 [2] c6 ce [2] c4 cf [2] df c9 [2] c3 ce [2] df e1 }

  condition:
    any of them
}