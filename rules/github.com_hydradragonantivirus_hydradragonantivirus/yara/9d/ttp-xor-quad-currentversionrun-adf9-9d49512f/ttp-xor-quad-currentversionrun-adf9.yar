rule TTP_XOR_QUAD_CurrentVersionRun_adf9 {
  strings:
    $key_adf9 = { fe 96 [2] da 98 [2] f1 b4 [2] df 96 [2] cb 8d [2] c4 97 [2] da 8a [2] d8 8b [2] c3 8d [2] df 8a [2] c3 a5 }

  condition:
    any of them
}