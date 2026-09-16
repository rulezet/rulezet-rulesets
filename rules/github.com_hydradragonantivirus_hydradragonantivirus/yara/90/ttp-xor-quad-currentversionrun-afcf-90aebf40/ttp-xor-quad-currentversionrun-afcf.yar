rule TTP_XOR_QUAD_CurrentVersionRun_afcf {
  strings:
    $key_afcf = { fc a0 [2] d8 ae [2] f3 82 [2] dd a0 [2] c9 bb [2] c6 a1 [2] d8 bc [2] da bd [2] c1 bb [2] dd bc [2] c1 93 }

  condition:
    any of them
}