rule TTP_XOR_QUAD_CurrentVersionRun_ad07 {
  strings:
    $key_ad07 = { fe 68 [2] da 66 [2] f1 4a [2] df 68 [2] cb 73 [2] c4 69 [2] da 74 [2] d8 75 [2] c3 73 [2] df 74 [2] c3 5b }

  condition:
    any of them
}