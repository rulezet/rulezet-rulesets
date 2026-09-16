rule TTP_XOR_QUAD_CurrentVersionRun_92d3 {
  strings:
    $key_92d3 = { c1 bc [2] e5 b2 [2] ce 9e [2] e0 bc [2] f4 a7 [2] fb bd [2] e5 a0 [2] e7 a1 [2] fc a7 [2] e0 a0 [2] fc 8f }

  condition:
    any of them
}