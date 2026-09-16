rule TTP_XOR_QUAD_CurrentVersionRun_ad2b {
  strings:
    $key_ad2b = { fe 44 [2] da 4a [2] f1 66 [2] df 44 [2] cb 5f [2] c4 45 [2] da 58 [2] d8 59 [2] c3 5f [2] df 58 [2] c3 77 }

  condition:
    any of them
}