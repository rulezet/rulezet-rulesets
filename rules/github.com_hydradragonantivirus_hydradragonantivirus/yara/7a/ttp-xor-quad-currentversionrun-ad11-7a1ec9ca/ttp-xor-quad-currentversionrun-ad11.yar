rule TTP_XOR_QUAD_CurrentVersionRun_ad11 {
  strings:
    $key_ad11 = { fe 7e [2] da 70 [2] f1 5c [2] df 7e [2] cb 65 [2] c4 7f [2] da 62 [2] d8 63 [2] c3 65 [2] df 62 [2] c3 4d }

  condition:
    any of them
}