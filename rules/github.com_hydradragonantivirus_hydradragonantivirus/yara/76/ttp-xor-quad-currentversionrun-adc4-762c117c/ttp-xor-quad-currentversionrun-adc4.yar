rule TTP_XOR_QUAD_CurrentVersionRun_adc4 {
  strings:
    $key_adc4 = { fe ab [2] da a5 [2] f1 89 [2] df ab [2] cb b0 [2] c4 aa [2] da b7 [2] d8 b6 [2] c3 b0 [2] df b7 [2] c3 98 }

  condition:
    any of them
}