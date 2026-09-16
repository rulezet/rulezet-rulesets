rule TTP_XOR_QUAD_CurrentVersionRun_f5e4 {
  strings:
    $key_f5e4 = { a6 8b [2] 82 85 [2] a9 a9 [2] 87 8b [2] 93 90 [2] 9c 8a [2] 82 97 [2] 80 96 [2] 9b 90 [2] 87 97 [2] 9b b8 }

  condition:
    any of them
}