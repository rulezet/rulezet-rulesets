rule TTP_XOR_QUAD_CurrentVersionRun_ffaa {
  strings:
    $key_ffaa = { ac c5 [2] 88 cb [2] a3 e7 [2] 8d c5 [2] 99 de [2] 96 c4 [2] 88 d9 [2] 8a d8 [2] 91 de [2] 8d d9 [2] 91 f6 }

  condition:
    any of them
}