rule TTP_XOR_QUAD_CurrentVersionRun_adc6 {
  strings:
    $key_adc6 = { fe a9 [2] da a7 [2] f1 8b [2] df a9 [2] cb b2 [2] c4 a8 [2] da b5 [2] d8 b4 [2] c3 b2 [2] df b5 [2] c3 9a }

  condition:
    any of them
}