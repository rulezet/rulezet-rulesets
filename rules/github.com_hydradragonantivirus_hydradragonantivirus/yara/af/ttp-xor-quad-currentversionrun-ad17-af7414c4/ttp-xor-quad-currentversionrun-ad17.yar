rule TTP_XOR_QUAD_CurrentVersionRun_ad17 {
  strings:
    $key_ad17 = { fe 78 [2] da 76 [2] f1 5a [2] df 78 [2] cb 63 [2] c4 79 [2] da 64 [2] d8 65 [2] c3 63 [2] df 64 [2] c3 4b }

  condition:
    any of them
}