rule TTP_XOR_QUAD_CurrentVersionRun_7ad7 {
  strings:
    $key_7ad7 = { 29 b8 [2] 0d b6 [2] 26 9a [2] 08 b8 [2] 1c a3 [2] 13 b9 [2] 0d a4 [2] 0f a5 [2] 14 a3 [2] 08 a4 [2] 14 8b }

  condition:
    any of them
}