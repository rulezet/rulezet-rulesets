rule TTP_XOR_QUAD_CurrentVersionRun_ad16 {
  strings:
    $key_ad16 = { fe 79 [2] da 77 [2] f1 5b [2] df 79 [2] cb 62 [2] c4 78 [2] da 65 [2] d8 64 [2] c3 62 [2] df 65 [2] c3 4a }

  condition:
    any of them
}