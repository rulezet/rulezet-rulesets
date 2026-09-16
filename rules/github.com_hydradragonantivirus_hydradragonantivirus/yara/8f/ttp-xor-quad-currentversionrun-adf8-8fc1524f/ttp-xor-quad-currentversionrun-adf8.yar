rule TTP_XOR_QUAD_CurrentVersionRun_adf8 {
  strings:
    $key_adf8 = { fe 97 [2] da 99 [2] f1 b5 [2] df 97 [2] cb 8c [2] c4 96 [2] da 8b [2] d8 8a [2] c3 8c [2] df 8b [2] c3 a4 }

  condition:
    any of them
}