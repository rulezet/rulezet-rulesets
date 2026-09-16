rule TTP_XOR_QUAD_CurrentVersionRun_ad7b {
  strings:
    $key_ad7b = { fe 14 [2] da 1a [2] f1 36 [2] df 14 [2] cb 0f [2] c4 15 [2] da 08 [2] d8 09 [2] c3 0f [2] df 08 [2] c3 27 }

  condition:
    any of them
}