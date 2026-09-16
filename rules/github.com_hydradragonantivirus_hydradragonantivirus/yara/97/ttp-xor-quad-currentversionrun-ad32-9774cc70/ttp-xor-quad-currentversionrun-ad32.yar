rule TTP_XOR_QUAD_CurrentVersionRun_ad32 {
  strings:
    $key_ad32 = { fe 5d [2] da 53 [2] f1 7f [2] df 5d [2] cb 46 [2] c4 5c [2] da 41 [2] d8 40 [2] c3 46 [2] df 41 [2] c3 6e }

  condition:
    any of them
}