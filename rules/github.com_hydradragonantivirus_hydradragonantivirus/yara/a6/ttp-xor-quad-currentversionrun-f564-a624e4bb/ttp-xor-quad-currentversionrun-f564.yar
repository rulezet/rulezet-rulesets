rule TTP_XOR_QUAD_CurrentVersionRun_f564 {
  strings:
    $key_f564 = { a6 0b [2] 82 05 [2] a9 29 [2] 87 0b [2] 93 10 [2] 9c 0a [2] 82 17 [2] 80 16 [2] 9b 10 [2] 87 17 [2] 9b 38 }

  condition:
    any of them
}