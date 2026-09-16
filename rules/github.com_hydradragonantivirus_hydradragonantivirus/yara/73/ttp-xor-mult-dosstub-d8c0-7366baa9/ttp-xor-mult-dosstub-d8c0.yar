rule TTP_XOR_MULT_DOSStub_d8c0 {
  strings:
    $key_d8c0 = { 8c a8 [2] f8 b0 [2] bf b2 [2] f8 a3 [2] b6 af [2] ba a5 [2] ad ae [2] b6 e0 [2] 8b }

  condition:
    any of them
}