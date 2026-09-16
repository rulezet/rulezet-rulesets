rule TTP_XOR_MULT_DOSStub_d1c0 {
  strings:
    $key_d1c0 = { 85 a8 [2] f1 b0 [2] b6 b2 [2] f1 a3 [2] bf af [2] b3 a5 [2] a4 ae [2] bf e0 [2] 82 }

  condition:
    any of them
}