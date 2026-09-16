rule TTP_XOR_QUAD_CurrentVersionRun_44aa {
  strings:
    $key_44aa = { 17 c5 [2] 33 cb [2] 18 e7 [2] 36 c5 [2] 22 de [2] 2d c4 [2] 33 d9 [2] 31 d8 [2] 2a de [2] 36 d9 [2] 2a f6 }

  condition:
    any of them
}