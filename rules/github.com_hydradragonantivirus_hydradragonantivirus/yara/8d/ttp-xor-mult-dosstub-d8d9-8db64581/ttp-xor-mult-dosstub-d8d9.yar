rule TTP_XOR_MULT_DOSStub_d8d9 {
  strings:
    $key_d8d9 = { 8c b1 [2] f8 a9 [2] bf ab [2] f8 ba [2] b6 b6 [2] ba bc [2] ad b7 [2] b6 f9 [2] 8b }

  condition:
    any of them
}