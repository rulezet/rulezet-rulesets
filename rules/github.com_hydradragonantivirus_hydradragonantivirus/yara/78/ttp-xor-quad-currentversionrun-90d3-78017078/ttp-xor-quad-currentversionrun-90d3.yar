rule TTP_XOR_QUAD_CurrentVersionRun_90d3 {
  strings:
    $key_90d3 = { c3 bc [2] e7 b2 [2] cc 9e [2] e2 bc [2] f6 a7 [2] f9 bd [2] e7 a0 [2] e5 a1 [2] fe a7 [2] e2 a0 [2] fe 8f }

  condition:
    any of them
}