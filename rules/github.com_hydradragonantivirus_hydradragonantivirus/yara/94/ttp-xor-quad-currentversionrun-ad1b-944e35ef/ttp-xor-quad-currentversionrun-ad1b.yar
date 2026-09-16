rule TTP_XOR_QUAD_CurrentVersionRun_ad1b {
  strings:
    $key_ad1b = { fe 74 [2] da 7a [2] f1 56 [2] df 74 [2] cb 6f [2] c4 75 [2] da 68 [2] d8 69 [2] c3 6f [2] df 68 [2] c3 47 }

  condition:
    any of them
}