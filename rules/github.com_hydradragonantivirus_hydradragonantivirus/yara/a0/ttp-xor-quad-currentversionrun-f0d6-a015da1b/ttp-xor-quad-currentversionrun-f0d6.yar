rule TTP_XOR_QUAD_CurrentVersionRun_f0d6 {
  strings:
    $key_f0d6 = { a3 b9 [2] 87 b7 [2] ac 9b [2] 82 b9 [2] 96 a2 [2] 99 b8 [2] 87 a5 [2] 85 a4 [2] 9e a2 [2] 82 a5 [2] 9e 8a }

  condition:
    any of them
}