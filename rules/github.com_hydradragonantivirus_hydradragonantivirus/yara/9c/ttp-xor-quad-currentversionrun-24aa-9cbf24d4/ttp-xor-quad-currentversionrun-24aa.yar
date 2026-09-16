rule TTP_XOR_QUAD_CurrentVersionRun_24aa {
  strings:
    $key_24aa = { 77 c5 [2] 53 cb [2] 78 e7 [2] 56 c5 [2] 42 de [2] 4d c4 [2] 53 d9 [2] 51 d8 [2] 4a de [2] 56 d9 [2] 4a f6 }

  condition:
    any of them
}