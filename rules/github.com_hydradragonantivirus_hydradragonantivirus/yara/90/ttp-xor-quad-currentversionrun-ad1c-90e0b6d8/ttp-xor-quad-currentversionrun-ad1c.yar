rule TTP_XOR_QUAD_CurrentVersionRun_ad1c {
  strings:
    $key_ad1c = { fe 73 [2] da 7d [2] f1 51 [2] df 73 [2] cb 68 [2] c4 72 [2] da 6f [2] d8 6e [2] c3 68 [2] df 6f [2] c3 40 }

  condition:
    any of them
}