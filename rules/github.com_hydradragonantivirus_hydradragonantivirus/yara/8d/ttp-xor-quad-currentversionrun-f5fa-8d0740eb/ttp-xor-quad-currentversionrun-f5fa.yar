rule TTP_XOR_QUAD_CurrentVersionRun_f5fa {
  strings:
    $key_f5fa = { a6 95 [2] 82 9b [2] a9 b7 [2] 87 95 [2] 93 8e [2] 9c 94 [2] 82 89 [2] 80 88 [2] 9b 8e [2] 87 89 [2] 9b a6 }

  condition:
    any of them
}