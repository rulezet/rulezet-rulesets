rule TTP_XOR_QUAD_CurrentVersionRun_7187 {
  strings:
    $key_7187 = { 22 e8 [2] 06 e6 [2] 2d ca [2] 03 e8 [2] 17 f3 [2] 18 e9 [2] 06 f4 [2] 04 f5 [2] 1f f3 [2] 03 f4 [2] 1f db }

  condition:
    any of them
}