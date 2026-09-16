rule TTP_XOR_QUAD_CurrentVersionRun_add5 {
  strings:
    $key_add5 = { fe ba [2] da b4 [2] f1 98 [2] df ba [2] cb a1 [2] c4 bb [2] da a6 [2] d8 a7 [2] c3 a1 [2] df a6 [2] c3 89 }

  condition:
    any of them
}