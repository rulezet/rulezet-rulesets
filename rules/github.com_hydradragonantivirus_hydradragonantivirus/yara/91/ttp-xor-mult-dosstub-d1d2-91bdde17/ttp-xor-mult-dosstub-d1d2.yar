rule TTP_XOR_MULT_DOSStub_d1d2 {
  strings:
    $key_d1d2 = { 85 ba [2] f1 a2 [2] b6 a0 [2] f1 b1 [2] bf bd [2] b3 b7 [2] a4 bc [2] bf f2 [2] 82 }

  condition:
    any of them
}