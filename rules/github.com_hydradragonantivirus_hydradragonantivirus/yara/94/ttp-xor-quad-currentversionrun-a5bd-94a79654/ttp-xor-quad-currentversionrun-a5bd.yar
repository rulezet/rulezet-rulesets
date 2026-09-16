rule TTP_XOR_QUAD_CurrentVersionRun_a5bd {
  strings:
    $key_a5bd = { f6 d2 [2] d2 dc [2] f9 f0 [2] d7 d2 [2] c3 c9 [2] cc d3 [2] d2 ce [2] d0 cf [2] cb c9 [2] d7 ce [2] cb e1 }

  condition:
    any of them
}