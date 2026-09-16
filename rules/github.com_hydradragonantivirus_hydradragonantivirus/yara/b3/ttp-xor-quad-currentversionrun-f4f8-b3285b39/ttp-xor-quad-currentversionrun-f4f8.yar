rule TTP_XOR_QUAD_CurrentVersionRun_f4f8 {
  strings:
    $key_f4f8 = { a7 97 [2] 83 99 [2] a8 b5 [2] 86 97 [2] 92 8c [2] 9d 96 [2] 83 8b [2] 81 8a [2] 9a 8c [2] 86 8b [2] 9a a4 }

  condition:
    any of them
}