rule TTP_XOR_QUAD_CurrentVersionRun_f6c7 {
  strings:
    $key_f6c7 = { a5 a8 [2] 81 a6 [2] aa 8a [2] 84 a8 [2] 90 b3 [2] 9f a9 [2] 81 b4 [2] 83 b5 [2] 98 b3 [2] 84 b4 [2] 98 9b }

  condition:
    any of them
}