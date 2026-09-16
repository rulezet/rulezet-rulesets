rule TTP_XOR_QUAD_CurrentVersionRun_f579 {
  strings:
    $key_f579 = { a6 16 [2] 82 18 [2] a9 34 [2] 87 16 [2] 93 0d [2] 9c 17 [2] 82 0a [2] 80 0b [2] 9b 0d [2] 87 0a [2] 9b 25 }

  condition:
    any of them
}