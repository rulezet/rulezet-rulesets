rule TTP_XOR_MULT_DOSStub_d8d6 {
  strings:
    $key_d8d6 = { 8c be [2] f8 a6 [2] bf a4 [2] f8 b5 [2] b6 b9 [2] ba b3 [2] ad b8 [2] b6 f6 [2] 8b }

  condition:
    any of them
}