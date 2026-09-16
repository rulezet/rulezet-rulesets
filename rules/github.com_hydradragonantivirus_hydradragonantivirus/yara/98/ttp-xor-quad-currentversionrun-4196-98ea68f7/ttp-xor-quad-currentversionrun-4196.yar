rule TTP_XOR_QUAD_CurrentVersionRun_4196 {
  strings:
    $key_4196 = { 12 f9 [2] 36 f7 [2] 1d db [2] 33 f9 [2] 27 e2 [2] 28 f8 [2] 36 e5 [2] 34 e4 [2] 2f e2 [2] 33 e5 [2] 2f ca }

  condition:
    any of them
}