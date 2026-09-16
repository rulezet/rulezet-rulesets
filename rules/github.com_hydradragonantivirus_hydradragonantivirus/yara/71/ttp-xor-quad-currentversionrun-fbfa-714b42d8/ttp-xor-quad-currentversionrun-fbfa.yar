rule TTP_XOR_QUAD_CurrentVersionRun_fbfa {
  strings:
    $key_fbfa = { a8 95 [2] 8c 9b [2] a7 b7 [2] 89 95 [2] 9d 8e [2] 92 94 [2] 8c 89 [2] 8e 88 [2] 95 8e [2] 89 89 [2] 95 a6 }

  condition:
    any of them
}