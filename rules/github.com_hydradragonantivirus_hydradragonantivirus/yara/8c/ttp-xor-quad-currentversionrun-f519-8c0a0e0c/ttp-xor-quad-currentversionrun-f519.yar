rule TTP_XOR_QUAD_CurrentVersionRun_f519 {
  strings:
    $key_f519 = { a6 76 [2] 82 78 [2] a9 54 [2] 87 76 [2] 93 6d [2] 9c 77 [2] 82 6a [2] 80 6b [2] 9b 6d [2] 87 6a [2] 9b 45 }

  condition:
    any of them
}