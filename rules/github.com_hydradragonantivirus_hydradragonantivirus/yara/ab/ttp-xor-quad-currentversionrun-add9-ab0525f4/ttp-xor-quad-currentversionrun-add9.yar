rule TTP_XOR_QUAD_CurrentVersionRun_add9 {
  strings:
    $key_add9 = { fe b6 [2] da b8 [2] f1 94 [2] df b6 [2] cb ad [2] c4 b7 [2] da aa [2] d8 ab [2] c3 ad [2] df aa [2] c3 85 }

  condition:
    any of them
}