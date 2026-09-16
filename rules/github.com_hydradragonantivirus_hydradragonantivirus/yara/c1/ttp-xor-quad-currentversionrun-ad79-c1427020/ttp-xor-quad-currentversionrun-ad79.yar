rule TTP_XOR_QUAD_CurrentVersionRun_ad79 {
  strings:
    $key_ad79 = { fe 16 [2] da 18 [2] f1 34 [2] df 16 [2] cb 0d [2] c4 17 [2] da 0a [2] d8 0b [2] c3 0d [2] df 0a [2] c3 25 }

  condition:
    any of them
}