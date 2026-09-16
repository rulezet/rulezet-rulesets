rule TTP_XOR_QUAD_CurrentVersionRun_ad74 {
  strings:
    $key_ad74 = { fe 1b [2] da 15 [2] f1 39 [2] df 1b [2] cb 00 [2] c4 1a [2] da 07 [2] d8 06 [2] c3 00 [2] df 07 [2] c3 28 }

  condition:
    any of them
}