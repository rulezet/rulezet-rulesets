rule TTP_XOR_QUAD_CurrentVersionRun_afd3 {
  strings:
    $key_afd3 = { fc bc [2] d8 b2 [2] f3 9e [2] dd bc [2] c9 a7 [2] c6 bd [2] d8 a0 [2] da a1 [2] c1 a7 [2] dd a0 [2] c1 8f }

  condition:
    any of them
}