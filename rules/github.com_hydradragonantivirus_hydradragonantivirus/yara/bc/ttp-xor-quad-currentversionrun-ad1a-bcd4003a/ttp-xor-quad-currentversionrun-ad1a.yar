rule TTP_XOR_QUAD_CurrentVersionRun_ad1a {
  strings:
    $key_ad1a = { fe 75 [2] da 7b [2] f1 57 [2] df 75 [2] cb 6e [2] c4 74 [2] da 69 [2] d8 68 [2] c3 6e [2] df 69 [2] c3 46 }

  condition:
    any of them
}