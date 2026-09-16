rule TTP_XOR_QUAD_CurrentVersionRun_f4e4 {
  strings:
    $key_f4e4 = { a7 8b [2] 83 85 [2] a8 a9 [2] 86 8b [2] 92 90 [2] 9d 8a [2] 83 97 [2] 81 96 [2] 9a 90 [2] 86 97 [2] 9a b8 }

  condition:
    any of them
}