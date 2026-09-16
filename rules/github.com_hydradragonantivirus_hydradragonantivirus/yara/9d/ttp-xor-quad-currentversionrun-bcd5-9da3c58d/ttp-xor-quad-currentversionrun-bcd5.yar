rule TTP_XOR_QUAD_CurrentVersionRun_bcd5 {
  strings:
    $key_bcd5 = { ef ba [2] cb b4 [2] e0 98 [2] ce ba [2] da a1 [2] d5 bb [2] cb a6 [2] c9 a7 [2] d2 a1 [2] ce a6 [2] d2 89 }

  condition:
    any of them
}