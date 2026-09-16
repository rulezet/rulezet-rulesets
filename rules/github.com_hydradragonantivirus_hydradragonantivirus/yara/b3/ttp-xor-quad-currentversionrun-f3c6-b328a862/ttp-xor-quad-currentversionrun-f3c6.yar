rule TTP_XOR_QUAD_CurrentVersionRun_f3c6 {
  strings:
    $key_f3c6 = { a0 a9 [2] 84 a7 [2] af 8b [2] 81 a9 [2] 95 b2 [2] 9a a8 [2] 84 b5 [2] 86 b4 [2] 9d b2 [2] 81 b5 [2] 9d 9a }

  condition:
    any of them
}