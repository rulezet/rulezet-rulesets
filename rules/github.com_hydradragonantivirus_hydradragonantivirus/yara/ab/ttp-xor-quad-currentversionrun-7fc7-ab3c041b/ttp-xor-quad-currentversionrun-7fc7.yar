rule TTP_XOR_QUAD_CurrentVersionRun_7fc7 {
  strings:
    $key_7fc7 = { 2c a8 [2] 08 a6 [2] 23 8a [2] 0d a8 [2] 19 b3 [2] 16 a9 [2] 08 b4 [2] 0a b5 [2] 11 b3 [2] 0d b4 [2] 11 9b }

  condition:
    any of them
}