rule TTP_XOR_MULT_DOSStub_d8c7 {
  strings:
    $key_d8c7 = { 8c af [2] f8 b7 [2] bf b5 [2] f8 a4 [2] b6 a8 [2] ba a2 [2] ad a9 [2] b6 e7 [2] 8b }

  condition:
    any of them
}