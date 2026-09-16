rule TTP_XOR_QUAD_CurrentVersionRun_ad6b {
  strings:
    $key_ad6b = { fe 04 [2] da 0a [2] f1 26 [2] df 04 [2] cb 1f [2] c4 05 [2] da 18 [2] d8 19 [2] c3 1f [2] df 18 [2] c3 37 }

  condition:
    any of them
}