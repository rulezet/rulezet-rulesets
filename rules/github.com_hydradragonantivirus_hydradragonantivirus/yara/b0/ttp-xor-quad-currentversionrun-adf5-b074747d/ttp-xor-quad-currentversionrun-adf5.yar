rule TTP_XOR_QUAD_CurrentVersionRun_adf5 {
  strings:
    $key_adf5 = { fe 9a [2] da 94 [2] f1 b8 [2] df 9a [2] cb 81 [2] c4 9b [2] da 86 [2] d8 87 [2] c3 81 [2] df 86 [2] c3 a9 }

  condition:
    any of them
}