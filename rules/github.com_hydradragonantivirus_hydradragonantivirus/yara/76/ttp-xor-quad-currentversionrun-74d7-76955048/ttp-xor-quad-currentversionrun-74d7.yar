rule TTP_XOR_QUAD_CurrentVersionRun_74d7 {
  strings:
    $key_74d7 = { 27 b8 [2] 03 b6 [2] 28 9a [2] 06 b8 [2] 12 a3 [2] 1d b9 [2] 03 a4 [2] 01 a5 [2] 1a a3 [2] 06 a4 [2] 1a 8b }

  condition:
    any of them
}