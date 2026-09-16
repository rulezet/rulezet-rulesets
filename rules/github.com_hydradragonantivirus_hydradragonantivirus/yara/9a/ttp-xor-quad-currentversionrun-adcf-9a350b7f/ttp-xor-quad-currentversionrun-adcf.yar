rule TTP_XOR_QUAD_CurrentVersionRun_adcf {
  strings:
    $key_adcf = { fe a0 [2] da ae [2] f1 82 [2] df a0 [2] cb bb [2] c4 a1 [2] da bc [2] d8 bd [2] c3 bb [2] df bc [2] c3 93 }

  condition:
    any of them
}