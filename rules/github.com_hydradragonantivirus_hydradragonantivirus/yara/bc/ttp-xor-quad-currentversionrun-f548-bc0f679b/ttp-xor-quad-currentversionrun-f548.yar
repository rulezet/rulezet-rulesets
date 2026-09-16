rule TTP_XOR_QUAD_CurrentVersionRun_f548 {
  strings:
    $key_f548 = { a6 27 [2] 82 29 [2] a9 05 [2] 87 27 [2] 93 3c [2] 9c 26 [2] 82 3b [2] 80 3a [2] 9b 3c [2] 87 3b [2] 9b 14 }

  condition:
    any of them
}