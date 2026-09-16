rule TTP_XOR_QUAD_CurrentVersionRun_4187 {
  strings:
    $key_4187 = { 12 e8 [2] 36 e6 [2] 1d ca [2] 33 e8 [2] 27 f3 [2] 28 e9 [2] 36 f4 [2] 34 f5 [2] 2f f3 [2] 33 f4 [2] 2f db }

  condition:
    any of them
}