rule TTP_XOR_QUAD_CurrentVersionRun_27aa {
  strings:
    $key_27aa = { 74 c5 [2] 50 cb [2] 7b e7 [2] 55 c5 [2] 41 de [2] 4e c4 [2] 50 d9 [2] 52 d8 [2] 49 de [2] 55 d9 [2] 49 f6 }

  condition:
    any of them
}