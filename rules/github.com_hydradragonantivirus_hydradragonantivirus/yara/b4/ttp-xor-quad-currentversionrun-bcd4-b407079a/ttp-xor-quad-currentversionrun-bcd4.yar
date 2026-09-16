rule TTP_XOR_QUAD_CurrentVersionRun_bcd4 {
  strings:
    $key_bcd4 = { ef bb [2] cb b5 [2] e0 99 [2] ce bb [2] da a0 [2] d5 ba [2] cb a7 [2] c9 a6 [2] d2 a0 [2] ce a7 [2] d2 88 }

  condition:
    any of them
}