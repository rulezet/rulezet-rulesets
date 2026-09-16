rule TTP_XOR_QUAD_CurrentVersionRun_ad24 {
  strings:
    $key_ad24 = { fe 4b [2] da 45 [2] f1 69 [2] df 4b [2] cb 50 [2] c4 4a [2] da 57 [2] d8 56 [2] c3 50 [2] df 57 [2] c3 78 }

  condition:
    any of them
}