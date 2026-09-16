rule TTP_XOR_QUAD_CurrentVersionRun_fbd6 {
  strings:
    $key_fbd6 = { a8 b9 [2] 8c b7 [2] a7 9b [2] 89 b9 [2] 9d a2 [2] 92 b8 [2] 8c a5 [2] 8e a4 [2] 95 a2 [2] 89 a5 [2] 95 8a }

  condition:
    any of them
}