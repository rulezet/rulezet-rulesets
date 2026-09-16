rule TTP_XOR_QUAD_CurrentVersionRun_b4bd {
  strings:
    $key_b4bd = { e7 d2 [2] c3 dc [2] e8 f0 [2] c6 d2 [2] d2 c9 [2] dd d3 [2] c3 ce [2] c1 cf [2] da c9 [2] c6 ce [2] da e1 }

  condition:
    any of them
}