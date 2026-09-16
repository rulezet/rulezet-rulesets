rule TTP_XOR_QUAD_CurrentVersionRun_ad50 {
  strings:
    $key_ad50 = { fe 3f [2] da 31 [2] f1 1d [2] df 3f [2] cb 24 [2] c4 3e [2] da 23 [2] d8 22 [2] c3 24 [2] df 23 [2] c3 0c }

  condition:
    any of them
}