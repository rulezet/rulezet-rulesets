rule TTP_XOR_QUAD_CurrentVersionRun_ad63 {
  strings:
    $key_ad63 = { fe 0c [2] da 02 [2] f1 2e [2] df 0c [2] cb 17 [2] c4 0d [2] da 10 [2] d8 11 [2] c3 17 [2] df 10 [2] c3 3f }

  condition:
    any of them
}