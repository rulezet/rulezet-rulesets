rule TTP_XOR_QUAD_CurrentVersionRun_f7aa {
  strings:
    $key_f7aa = { a4 c5 [2] 80 cb [2] ab e7 [2] 85 c5 [2] 91 de [2] 9e c4 [2] 80 d9 [2] 82 d8 [2] 99 de [2] 85 d9 [2] 99 f6 }

  condition:
    any of them
}