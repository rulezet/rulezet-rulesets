rule TTP_XOR_QUAD_CurrentVersionRun_ad6c {
  strings:
    $key_ad6c = { fe 03 [2] da 0d [2] f1 21 [2] df 03 [2] cb 18 [2] c4 02 [2] da 1f [2] d8 1e [2] c3 18 [2] df 1f [2] c3 30 }

  condition:
    any of them
}