rule TTP_XOR_QUAD_CurrentVersionRun_add8 {
  strings:
    $key_add8 = { fe b7 [2] da b9 [2] f1 95 [2] df b7 [2] cb ac [2] c4 b6 [2] da ab [2] d8 aa [2] c3 ac [2] df ab [2] c3 84 }

  condition:
    any of them
}