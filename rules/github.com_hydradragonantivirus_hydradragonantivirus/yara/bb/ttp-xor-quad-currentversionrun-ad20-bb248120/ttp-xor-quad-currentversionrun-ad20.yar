rule TTP_XOR_QUAD_CurrentVersionRun_ad20 {
  strings:
    $key_ad20 = { fe 4f [2] da 41 [2] f1 6d [2] df 4f [2] cb 54 [2] c4 4e [2] da 53 [2] d8 52 [2] c3 54 [2] df 53 [2] c3 7c }

  condition:
    any of them
}