rule TTP_XOR_QUAD_CurrentVersionRun_9ac9 {
  strings:
    $key_9ac9 = { c9 a6 [2] ed a8 [2] c6 84 [2] e8 a6 [2] fc bd [2] f3 a7 [2] ed ba [2] ef bb [2] f4 bd [2] e8 ba [2] f4 95 }

  condition:
    any of them
}