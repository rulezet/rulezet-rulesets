rule TTP_XOR_QUAD_CurrentVersionRun_cfc3 {
  strings:
    $key_cfc3 = { 9c ac [2] b8 a2 [2] 93 8e [2] bd ac [2] a9 b7 [2] a6 ad [2] b8 b0 [2] ba b1 [2] a1 b7 [2] bd b0 [2] a1 9f }

  condition:
    any of them
}