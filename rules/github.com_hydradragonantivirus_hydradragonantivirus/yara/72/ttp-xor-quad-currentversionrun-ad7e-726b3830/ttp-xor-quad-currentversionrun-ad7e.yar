rule TTP_XOR_QUAD_CurrentVersionRun_ad7e {
  strings:
    $key_ad7e = { fe 11 [2] da 1f [2] f1 33 [2] df 11 [2] cb 0a [2] c4 10 [2] da 0d [2] d8 0c [2] c3 0a [2] df 0d [2] c3 22 }

  condition:
    any of them
}