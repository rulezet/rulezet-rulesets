rule TTP_XOR_QUAD_CurrentVersionRun_adc9 {
  strings:
    $key_adc9 = { fe a6 [2] da a8 [2] f1 84 [2] df a6 [2] cb bd [2] c4 a7 [2] da ba [2] d8 bb [2] c3 bd [2] df ba [2] c3 95 }

  condition:
    any of them
}