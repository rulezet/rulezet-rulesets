rule TTP_XOR_QUAD_CurrentVersionRun_ad0c {
  strings:
    $key_ad0c = { fe 63 [2] da 6d [2] f1 41 [2] df 63 [2] cb 78 [2] c4 62 [2] da 7f [2] d8 7e [2] c3 78 [2] df 7f [2] c3 50 }

  condition:
    any of them
}