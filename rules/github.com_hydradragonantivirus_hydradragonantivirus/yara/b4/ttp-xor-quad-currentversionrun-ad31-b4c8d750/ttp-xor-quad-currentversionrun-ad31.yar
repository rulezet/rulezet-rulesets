rule TTP_XOR_QUAD_CurrentVersionRun_ad31 {
  strings:
    $key_ad31 = { fe 5e [2] da 50 [2] f1 7c [2] df 5e [2] cb 45 [2] c4 5f [2] da 42 [2] d8 43 [2] c3 45 [2] df 42 [2] c3 6d }

  condition:
    any of them
}