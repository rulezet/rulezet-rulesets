rule TTP_XOR_MULT_DOSStub_58b9 {
  strings:
    $key_58b9 = { 0c d1 [2] 78 c9 [2] 3f cb [2] 78 da [2] 36 d6 [2] 3a dc [2] 2d d7 [2] 36 99 [2] 0b }

  condition:
    any of them
}