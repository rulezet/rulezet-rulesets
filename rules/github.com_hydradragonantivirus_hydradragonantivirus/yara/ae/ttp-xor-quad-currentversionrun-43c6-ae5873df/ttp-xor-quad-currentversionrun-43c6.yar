rule TTP_XOR_QUAD_CurrentVersionRun_43c6 {
  strings:
    $key_43c6 = { 10 a9 [2] 34 a7 [2] 1f 8b [2] 31 a9 [2] 25 b2 [2] 2a a8 [2] 34 b5 [2] 36 b4 [2] 2d b2 [2] 31 b5 [2] 2d 9a }

  condition:
    any of them
}