rule TTP_XOR_MULT_DOSStub_d8b9 {
  strings:
    $key_d8b9 = { 8c d1 [2] f8 c9 [2] bf cb [2] f8 da [2] b6 d6 [2] ba dc [2] ad d7 [2] b6 99 [2] 8b }

  condition:
    any of them
}