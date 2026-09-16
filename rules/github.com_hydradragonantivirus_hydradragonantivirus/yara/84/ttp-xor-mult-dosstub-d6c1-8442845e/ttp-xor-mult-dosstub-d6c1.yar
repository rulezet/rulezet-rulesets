rule TTP_XOR_MULT_DOSStub_d6c1 {
  strings:
    $key_d6c1 = { 82 a9 [2] f6 b1 [2] b1 b3 [2] f6 a2 [2] b8 ae [2] b4 a4 [2] a3 af [2] b8 e1 [2] 85 }

  condition:
    any of them
}