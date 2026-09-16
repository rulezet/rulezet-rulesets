rule TTP_XOR_QUAD_CurrentVersionRun_ad23 {
  strings:
    $key_ad23 = { fe 4c [2] da 42 [2] f1 6e [2] df 4c [2] cb 57 [2] c4 4d [2] da 50 [2] d8 51 [2] c3 57 [2] df 50 [2] c3 7f }

  condition:
    any of them
}