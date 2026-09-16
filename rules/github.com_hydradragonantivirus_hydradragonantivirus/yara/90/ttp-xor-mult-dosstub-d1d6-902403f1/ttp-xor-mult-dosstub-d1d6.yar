rule TTP_XOR_MULT_DOSStub_d1d6 {
  strings:
    $key_d1d6 = { 85 be [2] f1 a6 [2] b6 a4 [2] f1 b5 [2] bf b9 [2] b3 b3 [2] a4 b8 [2] bf f6 [2] 82 }

  condition:
    any of them
}