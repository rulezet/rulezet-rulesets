rule TTP_XOR_QUAD_CurrentVersionRun_ad7f {
  strings:
    $key_ad7f = { fe 10 [2] da 1e [2] f1 32 [2] df 10 [2] cb 0b [2] c4 11 [2] da 0c [2] d8 0d [2] c3 0b [2] df 0c [2] c3 23 }

  condition:
    any of them
}