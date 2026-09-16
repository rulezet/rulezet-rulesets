rule TTP_XOR_QUAD_CurrentVersionRun_c8d3 {
  strings:
    $key_c8d3 = { 9b bc [2] bf b2 [2] 94 9e [2] ba bc [2] ae a7 [2] a1 bd [2] bf a0 [2] bd a1 [2] a6 a7 [2] ba a0 [2] a6 8f }

  condition:
    any of them
}