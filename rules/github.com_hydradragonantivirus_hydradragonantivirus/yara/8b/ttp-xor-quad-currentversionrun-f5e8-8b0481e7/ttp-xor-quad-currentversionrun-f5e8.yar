rule TTP_XOR_QUAD_CurrentVersionRun_f5e8 {
  strings:
    $key_f5e8 = { a6 87 [2] 82 89 [2] a9 a5 [2] 87 87 [2] 93 9c [2] 9c 86 [2] 82 9b [2] 80 9a [2] 9b 9c [2] 87 9b [2] 9b b4 }

  condition:
    any of them
}