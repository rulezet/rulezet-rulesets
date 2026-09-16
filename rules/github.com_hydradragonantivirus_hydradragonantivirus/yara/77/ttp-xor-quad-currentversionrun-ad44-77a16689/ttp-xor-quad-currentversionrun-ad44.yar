rule TTP_XOR_QUAD_CurrentVersionRun_ad44 {
  strings:
    $key_ad44 = { fe 2b [2] da 25 [2] f1 09 [2] df 2b [2] cb 30 [2] c4 2a [2] da 37 [2] d8 36 [2] c3 30 [2] df 37 [2] c3 18 }

  condition:
    any of them
}