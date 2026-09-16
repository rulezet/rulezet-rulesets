rule TTP_XOR_QUAD_CurrentVersionRun_ad67 {
  strings:
    $key_ad67 = { fe 08 [2] da 06 [2] f1 2a [2] df 08 [2] cb 13 [2] c4 09 [2] da 14 [2] d8 15 [2] c3 13 [2] df 14 [2] c3 3b }

  condition:
    any of them
}