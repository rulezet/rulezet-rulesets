rule TTP_XOR_QUAD_CurrentVersionRun_f525 {
  strings:
    $key_f525 = { a6 4a [2] 82 44 [2] a9 68 [2] 87 4a [2] 93 51 [2] 9c 4b [2] 82 56 [2] 80 57 [2] 9b 51 [2] 87 56 [2] 9b 79 }

  condition:
    any of them
}