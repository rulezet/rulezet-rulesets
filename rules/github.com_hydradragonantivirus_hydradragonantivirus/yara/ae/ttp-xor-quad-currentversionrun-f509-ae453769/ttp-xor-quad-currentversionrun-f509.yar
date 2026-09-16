rule TTP_XOR_QUAD_CurrentVersionRun_f509 {
  strings:
    $key_f509 = { a6 66 [2] 82 68 [2] a9 44 [2] 87 66 [2] 93 7d [2] 9c 67 [2] 82 7a [2] 80 7b [2] 9b 7d [2] 87 7a [2] 9b 55 }

  condition:
    any of them
}