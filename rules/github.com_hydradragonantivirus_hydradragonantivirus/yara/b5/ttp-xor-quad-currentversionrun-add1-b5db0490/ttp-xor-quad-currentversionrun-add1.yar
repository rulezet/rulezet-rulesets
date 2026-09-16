rule TTP_XOR_QUAD_CurrentVersionRun_add1 {
  strings:
    $key_add1 = { fe be [2] da b0 [2] f1 9c [2] df be [2] cb a5 [2] c4 bf [2] da a2 [2] d8 a3 [2] c3 a5 [2] df a2 [2] c3 8d }

  condition:
    any of them
}