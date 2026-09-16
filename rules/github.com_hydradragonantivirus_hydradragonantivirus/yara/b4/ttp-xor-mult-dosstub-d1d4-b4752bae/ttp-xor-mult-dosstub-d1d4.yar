rule TTP_XOR_MULT_DOSStub_d1d4 {
  strings:
    $key_d1d4 = { 85 bc [2] f1 a4 [2] b6 a6 [2] f1 b7 [2] bf bb [2] b3 b1 [2] a4 ba [2] bf f4 [2] 82 }

  condition:
    any of them
}