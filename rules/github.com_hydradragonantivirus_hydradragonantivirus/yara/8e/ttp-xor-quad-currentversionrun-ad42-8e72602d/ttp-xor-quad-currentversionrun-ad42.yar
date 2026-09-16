rule TTP_XOR_QUAD_CurrentVersionRun_ad42 {
  strings:
    $key_ad42 = { fe 2d [2] da 23 [2] f1 0f [2] df 2d [2] cb 36 [2] c4 2c [2] da 31 [2] d8 30 [2] c3 36 [2] df 31 [2] c3 1e }

  condition:
    any of them
}