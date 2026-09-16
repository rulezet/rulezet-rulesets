rule TTP_XOR_QUAD_CurrentVersionRun_ad08 {
  strings:
    $key_ad08 = { fe 67 [2] da 69 [2] f1 45 [2] df 67 [2] cb 7c [2] c4 66 [2] da 7b [2] d8 7a [2] c3 7c [2] df 7b [2] c3 54 }

  condition:
    any of them
}