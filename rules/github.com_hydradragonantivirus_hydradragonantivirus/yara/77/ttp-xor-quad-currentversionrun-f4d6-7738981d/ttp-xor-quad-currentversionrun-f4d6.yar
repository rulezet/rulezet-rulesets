rule TTP_XOR_QUAD_CurrentVersionRun_f4d6 {
  strings:
    $key_f4d6 = { a7 b9 [2] 83 b7 [2] a8 9b [2] 86 b9 [2] 92 a2 [2] 9d b8 [2] 83 a5 [2] 81 a4 [2] 9a a2 [2] 86 a5 [2] 9a 8a }

  condition:
    any of them
}