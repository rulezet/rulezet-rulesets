rule TTP_XOR_QUAD_CurrentVersionRun_ad26 {
  strings:
    $key_ad26 = { fe 49 [2] da 47 [2] f1 6b [2] df 49 [2] cb 52 [2] c4 48 [2] da 55 [2] d8 54 [2] c3 52 [2] df 55 [2] c3 7a }

  condition:
    any of them
}