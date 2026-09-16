rule TTP_XOR_QUAD_CurrentVersionRun_7fd6 {
  strings:
    $key_7fd6 = { 2c b9 [2] 08 b7 [2] 23 9b [2] 0d b9 [2] 19 a2 [2] 16 b8 [2] 08 a5 [2] 0a a4 [2] 11 a2 [2] 0d a5 [2] 11 8a }

  condition:
    any of them
}