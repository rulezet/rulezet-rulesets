rule TTP_XOR_QUAD_CurrentVersionRun_7fd7 {
  strings:
    $key_7fd7 = { 2c b8 [2] 08 b6 [2] 23 9a [2] 0d b8 [2] 19 a3 [2] 16 b9 [2] 08 a4 [2] 0a a5 [2] 11 a3 [2] 0d a4 [2] 11 8b }

  condition:
    any of them
}