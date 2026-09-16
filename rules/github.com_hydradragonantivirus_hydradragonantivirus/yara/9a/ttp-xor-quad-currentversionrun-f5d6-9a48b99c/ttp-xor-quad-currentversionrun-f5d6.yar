rule TTP_XOR_QUAD_CurrentVersionRun_f5d6 {
  strings:
    $key_f5d6 = { a6 b9 [2] 82 b7 [2] a9 9b [2] 87 b9 [2] 93 a2 [2] 9c b8 [2] 82 a5 [2] 80 a4 [2] 9b a2 [2] 87 a5 [2] 9b 8a }

  condition:
    any of them
}