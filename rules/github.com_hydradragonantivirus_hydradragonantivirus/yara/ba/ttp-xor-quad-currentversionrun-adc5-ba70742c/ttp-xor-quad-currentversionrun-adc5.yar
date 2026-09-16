rule TTP_XOR_QUAD_CurrentVersionRun_adc5 {
  strings:
    $key_adc5 = { fe aa [2] da a4 [2] f1 88 [2] df aa [2] cb b1 [2] c4 ab [2] da b6 [2] d8 b7 [2] c3 b1 [2] df b6 [2] c3 99 }

  condition:
    any of them
}