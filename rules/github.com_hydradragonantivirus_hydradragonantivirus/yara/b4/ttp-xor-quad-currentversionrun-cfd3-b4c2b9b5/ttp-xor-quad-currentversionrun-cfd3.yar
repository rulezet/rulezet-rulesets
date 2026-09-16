rule TTP_XOR_QUAD_CurrentVersionRun_cfd3 {
  strings:
    $key_cfd3 = { 9c bc [2] b8 b2 [2] 93 9e [2] bd bc [2] a9 a7 [2] a6 bd [2] b8 a0 [2] ba a1 [2] a1 a7 [2] bd a0 [2] a1 8f }

  condition:
    any of them
}