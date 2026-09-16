rule TTP_XOR_QUAD_CurrentVersionRun_c8c3 {
  strings:
    $key_c8c3 = { 9b ac [2] bf a2 [2] 94 8e [2] ba ac [2] ae b7 [2] a1 ad [2] bf b0 [2] bd b1 [2] a6 b7 [2] ba b0 [2] a6 9f }

  condition:
    any of them
}