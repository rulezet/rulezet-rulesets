rule TTP_XOR_QUAD_CurrentVersionRun_ad58 {
  strings:
    $key_ad58 = { fe 37 [2] da 39 [2] f1 15 [2] df 37 [2] cb 2c [2] c4 36 [2] da 2b [2] d8 2a [2] c3 2c [2] df 2b [2] c3 04 }

  condition:
    any of them
}