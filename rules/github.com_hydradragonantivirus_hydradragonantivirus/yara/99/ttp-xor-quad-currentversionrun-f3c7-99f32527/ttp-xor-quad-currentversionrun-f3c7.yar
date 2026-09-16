rule TTP_XOR_QUAD_CurrentVersionRun_f3c7 {
  strings:
    $key_f3c7 = { a0 a8 [2] 84 a6 [2] af 8a [2] 81 a8 [2] 95 b3 [2] 9a a9 [2] 84 b4 [2] 86 b5 [2] 9d b3 [2] 81 b4 [2] 9d 9b }

  condition:
    any of them
}