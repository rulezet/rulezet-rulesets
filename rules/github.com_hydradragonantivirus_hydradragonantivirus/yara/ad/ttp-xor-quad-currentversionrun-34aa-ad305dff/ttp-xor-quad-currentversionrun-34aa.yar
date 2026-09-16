rule TTP_XOR_QUAD_CurrentVersionRun_34aa {
  strings:
    $key_34aa = { 67 c5 [2] 43 cb [2] 68 e7 [2] 46 c5 [2] 52 de [2] 5d c4 [2] 43 d9 [2] 41 d8 [2] 5a de [2] 46 d9 [2] 5a f6 }

  condition:
    any of them
}