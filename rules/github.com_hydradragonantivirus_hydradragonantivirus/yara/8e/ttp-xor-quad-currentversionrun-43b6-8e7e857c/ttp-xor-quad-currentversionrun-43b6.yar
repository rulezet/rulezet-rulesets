rule TTP_XOR_QUAD_CurrentVersionRun_43b6 {
  strings:
    $key_43b6 = { 10 d9 [2] 34 d7 [2] 1f fb [2] 31 d9 [2] 25 c2 [2] 2a d8 [2] 34 c5 [2] 36 c4 [2] 2d c2 [2] 31 c5 [2] 2d ea }

  condition:
    any of them
}