rule TTP_XOR_QUAD_CurrentVersionRun_ad7a {
  strings:
    $key_ad7a = { fe 15 [2] da 1b [2] f1 37 [2] df 15 [2] cb 0e [2] c4 14 [2] da 09 [2] d8 08 [2] c3 0e [2] df 09 [2] c3 26 }

  condition:
    any of them
}