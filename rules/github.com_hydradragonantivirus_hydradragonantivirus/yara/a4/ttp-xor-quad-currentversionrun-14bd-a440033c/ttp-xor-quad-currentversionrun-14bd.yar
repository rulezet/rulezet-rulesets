rule TTP_XOR_QUAD_CurrentVersionRun_14bd {
  strings:
    $key_14bd = { 47 d2 [2] 63 dc [2] 48 f0 [2] 66 d2 [2] 72 c9 [2] 7d d3 [2] 63 ce [2] 61 cf [2] 7a c9 [2] 66 ce [2] 7a e1 }

  condition:
    any of them
}