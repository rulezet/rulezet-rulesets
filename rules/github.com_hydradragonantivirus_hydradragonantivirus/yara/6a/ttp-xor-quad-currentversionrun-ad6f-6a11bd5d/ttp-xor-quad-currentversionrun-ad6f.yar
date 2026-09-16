rule TTP_XOR_QUAD_CurrentVersionRun_ad6f {
  strings:
    $key_ad6f = { fe 00 [2] da 0e [2] f1 22 [2] df 00 [2] cb 1b [2] c4 01 [2] da 1c [2] d8 1d [2] c3 1b [2] df 1c [2] c3 33 }

  condition:
    any of them
}