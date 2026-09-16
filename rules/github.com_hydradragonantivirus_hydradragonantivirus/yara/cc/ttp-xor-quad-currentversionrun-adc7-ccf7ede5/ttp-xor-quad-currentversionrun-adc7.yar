rule TTP_XOR_QUAD_CurrentVersionRun_adc7 {
  strings:
    $key_adc7 = { fe a8 [2] da a6 [2] f1 8a [2] df a8 [2] cb b3 [2] c4 a9 [2] da b4 [2] d8 b5 [2] c3 b3 [2] df b4 [2] c3 9b }

  condition:
    any of them
}