rule TTP_XOR_QUAD_CurrentVersionRun_ad4e {
  strings:
    $key_ad4e = { fe 21 [2] da 2f [2] f1 03 [2] df 21 [2] cb 3a [2] c4 20 [2] da 3d [2] d8 3c [2] c3 3a [2] df 3d [2] c3 12 }

  condition:
    any of them
}