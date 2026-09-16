rule TTP_XOR_QUAD_CurrentVersionRun_ad62 {
  strings:
    $key_ad62 = { fe 0d [2] da 03 [2] f1 2f [2] df 0d [2] cb 16 [2] c4 0c [2] da 11 [2] d8 10 [2] c3 16 [2] df 11 [2] c3 3e }

  condition:
    any of them
}