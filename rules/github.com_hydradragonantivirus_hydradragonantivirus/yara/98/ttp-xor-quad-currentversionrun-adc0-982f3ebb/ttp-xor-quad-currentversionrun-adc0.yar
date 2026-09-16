rule TTP_XOR_QUAD_CurrentVersionRun_adc0 {
  strings:
    $key_adc0 = { fe af [2] da a1 [2] f1 8d [2] df af [2] cb b4 [2] c4 ae [2] da b3 [2] d8 b2 [2] c3 b4 [2] df b3 [2] c3 9c }

  condition:
    any of them
}