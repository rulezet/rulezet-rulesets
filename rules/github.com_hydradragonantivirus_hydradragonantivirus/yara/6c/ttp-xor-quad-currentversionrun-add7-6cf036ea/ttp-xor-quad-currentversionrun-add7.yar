rule TTP_XOR_QUAD_CurrentVersionRun_add7 {
  strings:
    $key_add7 = { fe b8 [2] da b6 [2] f1 9a [2] df b8 [2] cb a3 [2] c4 b9 [2] da a4 [2] d8 a5 [2] c3 a3 [2] df a4 [2] c3 8b }

  condition:
    any of them
}