rule TTP_XOR_QUAD_CurrentVersionRun_ad52 {
  strings:
    $key_ad52 = { fe 3d [2] da 33 [2] f1 1f [2] df 3d [2] cb 26 [2] c4 3c [2] da 21 [2] d8 20 [2] c3 26 [2] df 21 [2] c3 0e }

  condition:
    any of them
}