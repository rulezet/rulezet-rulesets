rule TTP_XOR_MULT_DOSStub_d8b1 {
  strings:
    $key_d8b1 = { 8c d9 [2] f8 c1 [2] bf c3 [2] f8 d2 [2] b6 de [2] ba d4 [2] ad df [2] b6 91 [2] 8b }

  condition:
    any of them
}