rule TTP_XOR_QUAD_CurrentVersionRun_5ec6 {
  strings:
    $key_5ec6 = { 0d a9 [2] 29 a7 [2] 02 8b [2] 2c a9 [2] 38 b2 [2] 37 a8 [2] 29 b5 [2] 2b b4 [2] 30 b2 [2] 2c b5 [2] 30 9a }

  condition:
    any of them
}