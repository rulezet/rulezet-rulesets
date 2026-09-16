rule TTP_XOR_QUAD_CurrentVersionRun_ad3b {
  strings:
    $key_ad3b = { fe 54 [2] da 5a [2] f1 76 [2] df 54 [2] cb 4f [2] c4 55 [2] da 48 [2] d8 49 [2] c3 4f [2] df 48 [2] c3 67 }

  condition:
    any of them
}