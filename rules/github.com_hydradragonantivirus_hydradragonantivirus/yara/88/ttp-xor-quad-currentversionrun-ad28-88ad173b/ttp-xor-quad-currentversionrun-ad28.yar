rule TTP_XOR_QUAD_CurrentVersionRun_ad28 {
  strings:
    $key_ad28 = { fe 47 [2] da 49 [2] f1 65 [2] df 47 [2] cb 5c [2] c4 46 [2] da 5b [2] d8 5a [2] c3 5c [2] df 5b [2] c3 74 }

  condition:
    any of them
}