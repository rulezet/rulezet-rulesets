rule TTP_XOR_QUAD_CurrentVersionRun_e4aa {
  strings:
    $key_e4aa = { b7 c5 [2] 93 cb [2] b8 e7 [2] 96 c5 [2] 82 de [2] 8d c4 [2] 93 d9 [2] 91 d8 [2] 8a de [2] 96 d9 [2] 8a f6 }

  condition:
    any of them
}