rule TTP_XOR_QUAD_CurrentVersionRun_ad12 {
  strings:
    $key_ad12 = { fe 7d [2] da 73 [2] f1 5f [2] df 7d [2] cb 66 [2] c4 7c [2] da 61 [2] d8 60 [2] c3 66 [2] df 61 [2] c3 4e }

  condition:
    any of them
}