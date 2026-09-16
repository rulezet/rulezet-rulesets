rule TTP_XOR_QUAD_CurrentVersionRun_67a4 {
  strings:
    $key_67a4 = { 34 cb [2] 10 c5 [2] 3b e9 [2] 15 cb [2] 01 d0 [2] 0e ca [2] 10 d7 [2] 12 d6 [2] 09 d0 [2] 15 d7 [2] 09 f8 }

  condition:
    any of them
}