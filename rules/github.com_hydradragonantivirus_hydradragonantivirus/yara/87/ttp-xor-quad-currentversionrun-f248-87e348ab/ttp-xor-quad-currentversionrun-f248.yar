rule TTP_XOR_QUAD_CurrentVersionRun_f248 {
  strings:
    $key_f248 = { a1 27 [2] 85 29 [2] ae 05 [2] 80 27 [2] 94 3c [2] 9b 26 [2] 85 3b [2] 87 3a [2] 9c 3c [2] 80 3b [2] 9c 14 }

  condition:
    any of them
}