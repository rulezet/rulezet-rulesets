rule TTP_XOR_QUAD_CurrentVersionRun_0ad7 {
  strings:
    $key_0ad7 = { 59 b8 [2] 7d b6 [2] 56 9a [2] 78 b8 [2] 6c a3 [2] 63 b9 [2] 7d a4 [2] 7f a5 [2] 64 a3 [2] 78 a4 [2] 64 8b }

  condition:
    any of them
}