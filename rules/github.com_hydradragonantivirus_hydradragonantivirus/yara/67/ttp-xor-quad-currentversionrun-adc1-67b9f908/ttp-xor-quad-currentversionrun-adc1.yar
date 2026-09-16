rule TTP_XOR_QUAD_CurrentVersionRun_adc1 {
  strings:
    $key_adc1 = { fe ae [2] da a0 [2] f1 8c [2] df ae [2] cb b5 [2] c4 af [2] da b2 [2] d8 b3 [2] c3 b5 [2] df b2 [2] c3 9d }

  condition:
    any of them
}