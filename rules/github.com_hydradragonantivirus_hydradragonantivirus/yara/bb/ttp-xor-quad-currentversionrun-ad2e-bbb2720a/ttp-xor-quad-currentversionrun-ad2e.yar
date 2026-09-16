rule TTP_XOR_QUAD_CurrentVersionRun_ad2e {
  strings:
    $key_ad2e = { fe 41 [2] da 4f [2] f1 63 [2] df 41 [2] cb 5a [2] c4 40 [2] da 5d [2] d8 5c [2] c3 5a [2] df 5d [2] c3 72 }

  condition:
    any of them
}