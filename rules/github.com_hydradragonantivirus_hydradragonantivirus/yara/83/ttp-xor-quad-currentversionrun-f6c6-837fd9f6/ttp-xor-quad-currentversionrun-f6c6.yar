rule TTP_XOR_QUAD_CurrentVersionRun_f6c6 {
  strings:
    $key_f6c6 = { a5 a9 [2] 81 a7 [2] aa 8b [2] 84 a9 [2] 90 b2 [2] 9f a8 [2] 81 b5 [2] 83 b4 [2] 98 b2 [2] 84 b5 [2] 98 9a }

  condition:
    any of them
}