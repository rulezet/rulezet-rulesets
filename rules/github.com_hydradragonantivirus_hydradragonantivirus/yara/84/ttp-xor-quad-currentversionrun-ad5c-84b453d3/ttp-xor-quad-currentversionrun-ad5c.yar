rule TTP_XOR_QUAD_CurrentVersionRun_ad5c {
  strings:
    $key_ad5c = { fe 33 [2] da 3d [2] f1 11 [2] df 33 [2] cb 28 [2] c4 32 [2] da 2f [2] d8 2e [2] c3 28 [2] df 2f [2] c3 00 }

  condition:
    any of them
}