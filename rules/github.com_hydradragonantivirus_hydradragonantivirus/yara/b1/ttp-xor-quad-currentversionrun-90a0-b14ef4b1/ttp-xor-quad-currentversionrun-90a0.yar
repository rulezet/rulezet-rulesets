rule TTP_XOR_QUAD_CurrentVersionRun_90a0 {
  strings:
    $key_90a0 = { c3 cf [2] e7 c1 [2] cc ed [2] e2 cf [2] f6 d4 [2] f9 ce [2] e7 d3 [2] e5 d2 [2] fe d4 [2] e2 d3 [2] fe fc }

  condition:
    any of them
}