rule TTP_XOR_QUAD_CurrentVersionRun_64c7 {
  strings:
    $key_64c7 = { 37 a8 [2] 13 a6 [2] 38 8a [2] 16 a8 [2] 02 b3 [2] 0d a9 [2] 13 b4 [2] 11 b5 [2] 0a b3 [2] 16 b4 [2] 0a 9b }

  condition:
    any of them
}