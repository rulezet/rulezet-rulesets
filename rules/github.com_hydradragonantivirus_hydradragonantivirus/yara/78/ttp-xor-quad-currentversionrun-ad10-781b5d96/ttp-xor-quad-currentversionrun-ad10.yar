rule TTP_XOR_QUAD_CurrentVersionRun_ad10 {
  strings:
    $key_ad10 = { fe 7f [2] da 71 [2] f1 5d [2] df 7f [2] cb 64 [2] c4 7e [2] da 63 [2] d8 62 [2] c3 64 [2] df 63 [2] c3 4c }

  condition:
    any of them
}