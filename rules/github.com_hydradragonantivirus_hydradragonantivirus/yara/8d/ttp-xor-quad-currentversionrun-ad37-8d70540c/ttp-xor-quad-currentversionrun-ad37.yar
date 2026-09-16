rule TTP_XOR_QUAD_CurrentVersionRun_ad37 {
  strings:
    $key_ad37 = { fe 58 [2] da 56 [2] f1 7a [2] df 58 [2] cb 43 [2] c4 59 [2] da 44 [2] d8 45 [2] c3 43 [2] df 44 [2] c3 6b }

  condition:
    any of them
}