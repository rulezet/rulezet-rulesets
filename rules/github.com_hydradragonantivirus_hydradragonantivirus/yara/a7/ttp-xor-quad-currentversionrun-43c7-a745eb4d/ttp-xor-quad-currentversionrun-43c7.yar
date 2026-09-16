rule TTP_XOR_QUAD_CurrentVersionRun_43c7 {
  strings:
    $key_43c7 = { 10 a8 [2] 34 a6 [2] 1f 8a [2] 31 a8 [2] 25 b3 [2] 2a a9 [2] 34 b4 [2] 36 b5 [2] 2d b3 [2] 31 b4 [2] 2d 9b }

  condition:
    any of them
}