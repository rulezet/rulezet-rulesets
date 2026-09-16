rule TTP_XOR_QUAD_CurrentVersionRun_f4aa {
  strings:
    $key_f4aa = { a7 c5 [2] 83 cb [2] a8 e7 [2] 86 c5 [2] 92 de [2] 9d c4 [2] 83 d9 [2] 81 d8 [2] 9a de [2] 86 d9 [2] 9a f6 }

  condition:
    any of them
}