rule TTP_XOR_QUAD_CurrentVersionRun_bcd2 {
  strings:
    $key_bcd2 = { ef bd [2] cb b3 [2] e0 9f [2] ce bd [2] da a6 [2] d5 bc [2] cb a1 [2] c9 a0 [2] d2 a6 [2] ce a1 [2] d2 8e }

  condition:
    any of them
}