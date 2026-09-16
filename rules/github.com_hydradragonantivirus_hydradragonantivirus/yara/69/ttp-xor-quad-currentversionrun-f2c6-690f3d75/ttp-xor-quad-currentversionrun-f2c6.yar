rule TTP_XOR_QUAD_CurrentVersionRun_f2c6 {
  strings:
    $key_f2c6 = { a1 a9 [2] 85 a7 [2] ae 8b [2] 80 a9 [2] 94 b2 [2] 9b a8 [2] 85 b5 [2] 87 b4 [2] 9c b2 [2] 80 b5 [2] 9c 9a }

  condition:
    any of them
}