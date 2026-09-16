rule TTP_XOR_QUAD_CurrentVersionRun_45d6 {
  strings:
    $key_45d6 = { 16 b9 [2] 32 b7 [2] 19 9b [2] 37 b9 [2] 23 a2 [2] 2c b8 [2] 32 a5 [2] 30 a4 [2] 2b a2 [2] 37 a5 [2] 2b 8a }

  condition:
    any of them
}