rule TTP_XOR_QUAD_CurrentVersionRun_ad29 {
  strings:
    $key_ad29 = { fe 46 [2] da 48 [2] f1 64 [2] df 46 [2] cb 5d [2] c4 47 [2] da 5a [2] d8 5b [2] c3 5d [2] df 5a [2] c3 75 }

  condition:
    any of them
}