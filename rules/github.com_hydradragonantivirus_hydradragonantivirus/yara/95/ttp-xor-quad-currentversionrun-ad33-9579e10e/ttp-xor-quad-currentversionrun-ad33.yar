rule TTP_XOR_QUAD_CurrentVersionRun_ad33 {
  strings:
    $key_ad33 = { fe 5c [2] da 52 [2] f1 7e [2] df 5c [2] cb 47 [2] c4 5d [2] da 40 [2] d8 41 [2] c3 47 [2] df 40 [2] c3 6f }

  condition:
    any of them
}