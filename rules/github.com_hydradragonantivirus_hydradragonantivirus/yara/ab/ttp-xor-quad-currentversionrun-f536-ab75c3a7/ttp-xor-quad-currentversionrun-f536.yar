rule TTP_XOR_QUAD_CurrentVersionRun_f536 {
  strings:
    $key_f536 = { a6 59 [2] 82 57 [2] a9 7b [2] 87 59 [2] 93 42 [2] 9c 58 [2] 82 45 [2] 80 44 [2] 9b 42 [2] 87 45 [2] 9b 6a }

  condition:
    any of them
}