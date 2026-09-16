rule TTP_XOR_QUAD_CurrentVersionRun_4396 {
  strings:
    $key_4396 = { 10 f9 [2] 34 f7 [2] 1f db [2] 31 f9 [2] 25 e2 [2] 2a f8 [2] 34 e5 [2] 36 e4 [2] 2d e2 [2] 31 e5 [2] 2d ca }

  condition:
    any of them
}