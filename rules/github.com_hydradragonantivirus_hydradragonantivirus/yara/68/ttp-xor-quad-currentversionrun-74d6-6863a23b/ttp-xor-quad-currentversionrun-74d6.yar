rule TTP_XOR_QUAD_CurrentVersionRun_74d6 {
  strings:
    $key_74d6 = { 27 b9 [2] 03 b7 [2] 28 9b [2] 06 b9 [2] 12 a2 [2] 1d b8 [2] 03 a5 [2] 01 a4 [2] 1a a2 [2] 06 a5 [2] 1a 8a }

  condition:
    any of them
}