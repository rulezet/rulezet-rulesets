rule TTP_XOR_QUAD_CurrentVersionRun_2ad7 {
  strings:
    $key_2ad7 = { 79 b8 [2] 5d b6 [2] 76 9a [2] 58 b8 [2] 4c a3 [2] 43 b9 [2] 5d a4 [2] 5f a5 [2] 44 a3 [2] 58 a4 [2] 44 8b }

  condition:
    any of them
}