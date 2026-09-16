rule TTP_XOR_QUAD_CurrentVersionRun_74c7 {
  strings:
    $key_74c7 = { 27 a8 [2] 03 a6 [2] 28 8a [2] 06 a8 [2] 12 b3 [2] 1d a9 [2] 03 b4 [2] 01 b5 [2] 1a b3 [2] 06 b4 [2] 1a 9b }

  condition:
    any of them
}