rule TTP_XOR_QUAD_CurrentVersionRun_acd3 {
  strings:
    $key_acd3 = { ff bc [2] db b2 [2] f0 9e [2] de bc [2] ca a7 [2] c5 bd [2] db a0 [2] d9 a1 [2] c2 a7 [2] de a0 [2] c2 8f }

  condition:
    any of them
}