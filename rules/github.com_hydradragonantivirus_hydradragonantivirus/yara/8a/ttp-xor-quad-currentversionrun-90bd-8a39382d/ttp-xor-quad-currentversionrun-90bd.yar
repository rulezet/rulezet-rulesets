rule TTP_XOR_QUAD_CurrentVersionRun_90bd {
  strings:
    $key_90bd = { c3 d2 [2] e7 dc [2] cc f0 [2] e2 d2 [2] f6 c9 [2] f9 d3 [2] e7 ce [2] e5 cf [2] fe c9 [2] e2 ce [2] fe e1 }

  condition:
    any of them
}