rule TTP_XOR_QUAD_CurrentVersionRun_ad27 {
  strings:
    $key_ad27 = { fe 48 [2] da 46 [2] f1 6a [2] df 48 [2] cb 53 [2] c4 49 [2] da 54 [2] d8 55 [2] c3 53 [2] df 54 [2] c3 7b }

  condition:
    any of them
}