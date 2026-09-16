rule TTP_XOR_QUAD_CurrentVersionRun_add3 {
  strings:
    $key_add3 = { fe bc [2] da b2 [2] f1 9e [2] df bc [2] cb a7 [2] c4 bd [2] da a0 [2] d8 a1 [2] c3 a7 [2] df a0 [2] c3 8f }

  condition:
    any of them
}