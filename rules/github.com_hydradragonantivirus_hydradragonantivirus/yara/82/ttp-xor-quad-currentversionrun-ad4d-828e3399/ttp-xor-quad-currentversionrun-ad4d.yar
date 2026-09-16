rule TTP_XOR_QUAD_CurrentVersionRun_ad4d {
  strings:
    $key_ad4d = { fe 22 [2] da 2c [2] f1 00 [2] df 22 [2] cb 39 [2] c4 23 [2] da 3e [2] d8 3f [2] c3 39 [2] df 3e [2] c3 11 }

  condition:
    any of them
}