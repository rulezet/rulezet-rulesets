rule TTP_XOR_QUAD_CurrentVersionRun_ad76 {
  strings:
    $key_ad76 = { fe 19 [2] da 17 [2] f1 3b [2] df 19 [2] cb 02 [2] c4 18 [2] da 05 [2] d8 04 [2] c3 02 [2] df 05 [2] c3 2a }

  condition:
    any of them
}