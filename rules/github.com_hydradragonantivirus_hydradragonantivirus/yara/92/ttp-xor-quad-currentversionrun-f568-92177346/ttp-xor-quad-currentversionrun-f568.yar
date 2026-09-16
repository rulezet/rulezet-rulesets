rule TTP_XOR_QUAD_CurrentVersionRun_f568 {
  strings:
    $key_f568 = { a6 07 [2] 82 09 [2] a9 25 [2] 87 07 [2] 93 1c [2] 9c 06 [2] 82 1b [2] 80 1a [2] 9b 1c [2] 87 1b [2] 9b 34 }

  condition:
    any of them
}