rule TTP_XOR_QUAD_CurrentVersionRun_f6d6 {
  strings:
    $key_f6d6 = { a5 b9 [2] 81 b7 [2] aa 9b [2] 84 b9 [2] 90 a2 [2] 9f b8 [2] 81 a5 [2] 83 a4 [2] 98 a2 [2] 84 a5 [2] 98 8a }

  condition:
    any of them
}