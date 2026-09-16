rule TTP_XOR_QUAD_CurrentVersionRun_add6 {
  strings:
    $key_add6 = { fe b9 [2] da b7 [2] f1 9b [2] df b9 [2] cb a2 [2] c4 b8 [2] da a5 [2] d8 a4 [2] c3 a2 [2] df a5 [2] c3 8a }

  condition:
    any of them
}