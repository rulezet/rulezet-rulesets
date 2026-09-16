rule TTP_XOR_QUAD_CurrentVersionRun_f2d5 {
  strings:
    $key_f2d5 = { a1 ba [2] 85 b4 [2] ae 98 [2] 80 ba [2] 94 a1 [2] 9b bb [2] 85 a6 [2] 87 a7 [2] 9c a1 [2] 80 a6 [2] 9c 89 }

  condition:
    any of them
}