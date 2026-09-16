rule TTP_XOR_QUAD_CurrentVersionRun_bcd3 {
  strings:
    $key_bcd3 = { ef bc [2] cb b2 [2] e0 9e [2] ce bc [2] da a7 [2] d5 bd [2] cb a0 [2] c9 a1 [2] d2 a7 [2] ce a0 [2] d2 8f }

  condition:
    any of them
}