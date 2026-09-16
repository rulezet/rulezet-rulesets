rule TTP_XOR_QUAD_CurrentVersionRun_f4fa {
  strings:
    $key_f4fa = { a7 95 [2] 83 9b [2] a8 b7 [2] 86 95 [2] 92 8e [2] 9d 94 [2] 83 89 [2] 81 88 [2] 9a 8e [2] 86 89 [2] 9a a6 }

  condition:
    any of them
}