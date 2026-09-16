rule TTP_XOR_QUAD_CurrentVersionRun_ad2f {
  strings:
    $key_ad2f = { fe 40 [2] da 4e [2] f1 62 [2] df 40 [2] cb 5b [2] c4 41 [2] da 5c [2] d8 5d [2] c3 5b [2] df 5c [2] c3 73 }

  condition:
    any of them
}