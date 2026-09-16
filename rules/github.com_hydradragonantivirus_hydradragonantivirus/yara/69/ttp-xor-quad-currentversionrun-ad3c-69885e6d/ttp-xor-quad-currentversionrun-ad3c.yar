rule TTP_XOR_QUAD_CurrentVersionRun_ad3c {
  strings:
    $key_ad3c = { fe 53 [2] da 5d [2] f1 71 [2] df 53 [2] cb 48 [2] c4 52 [2] da 4f [2] d8 4e [2] c3 48 [2] df 4f [2] c3 60 }

  condition:
    any of them
}