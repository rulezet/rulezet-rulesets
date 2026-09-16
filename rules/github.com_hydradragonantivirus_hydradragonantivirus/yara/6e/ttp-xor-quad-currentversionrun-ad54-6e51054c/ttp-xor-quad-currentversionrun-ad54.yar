rule TTP_XOR_QUAD_CurrentVersionRun_ad54 {
  strings:
    $key_ad54 = { fe 3b [2] da 35 [2] f1 19 [2] df 3b [2] cb 20 [2] c4 3a [2] da 27 [2] d8 26 [2] c3 20 [2] df 27 [2] c3 08 }

  condition:
    any of them
}