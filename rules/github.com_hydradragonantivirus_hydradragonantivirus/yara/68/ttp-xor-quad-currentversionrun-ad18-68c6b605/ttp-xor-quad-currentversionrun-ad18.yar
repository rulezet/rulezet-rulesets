rule TTP_XOR_QUAD_CurrentVersionRun_ad18 {
  strings:
    $key_ad18 = { fe 77 [2] da 79 [2] f1 55 [2] df 77 [2] cb 6c [2] c4 76 [2] da 6b [2] d8 6a [2] c3 6c [2] df 6b [2] c3 44 }

  condition:
    any of them
}