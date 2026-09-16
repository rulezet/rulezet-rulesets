rule TTP_XOR_QUAD_CurrentVersionRun_92a7 {
  strings:
    $key_92a7 = { c1 c8 [2] e5 c6 [2] ce ea [2] e0 c8 [2] f4 d3 [2] fb c9 [2] e5 d4 [2] e7 d5 [2] fc d3 [2] e0 d4 [2] fc fb }

  condition:
    any of them
}