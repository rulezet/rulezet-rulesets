rule TTP_XOR_QUAD_CurrentVersionRun_ad30 {
  strings:
    $key_ad30 = { fe 5f [2] da 51 [2] f1 7d [2] df 5f [2] cb 44 [2] c4 5e [2] da 43 [2] d8 42 [2] c3 44 [2] df 43 [2] c3 6c }

  condition:
    any of them
}