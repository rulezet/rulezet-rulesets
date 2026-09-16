rule TTP_XOR_QUAD_CurrentVersionRun_ad68 {
  strings:
    $key_ad68 = { fe 07 [2] da 09 [2] f1 25 [2] df 07 [2] cb 1c [2] c4 06 [2] da 1b [2] d8 1a [2] c3 1c [2] df 1b [2] c3 34 }

  condition:
    any of them
}