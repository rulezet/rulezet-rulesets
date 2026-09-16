rule TTP_XOR_QUAD_CurrentVersionRun_addf {
  strings:
    $key_addf = { fe b0 [2] da be [2] f1 92 [2] df b0 [2] cb ab [2] c4 b1 [2] da ac [2] d8 ad [2] c3 ab [2] df ac [2] c3 83 }

  condition:
    any of them
}