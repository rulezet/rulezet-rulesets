rule TTP_XOR_QUAD_CurrentVersionRun_43d5 {
  strings:
    $key_43d5 = { 10 ba [2] 34 b4 [2] 1f 98 [2] 31 ba [2] 25 a1 [2] 2a bb [2] 34 a6 [2] 36 a7 [2] 2d a1 [2] 31 a6 [2] 2d 89 }

  condition:
    any of them
}