rule TTP_XOR_QUAD_CurrentVersionRun_f4a4 {
  strings:
    $key_f4a4 = { a7 cb [2] 83 c5 [2] a8 e9 [2] 86 cb [2] 92 d0 [2] 9d ca [2] 83 d7 [2] 81 d6 [2] 9a d0 [2] 86 d7 [2] 9a f8 }

  condition:
    any of them
}