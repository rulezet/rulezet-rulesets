rule TTP_XOR_MULT_DOSStub_d7c1 {
  strings:
    $key_d7c1 = { 83 a9 [2] f7 b1 [2] b0 b3 [2] f7 a2 [2] b9 ae [2] b5 a4 [2] a2 af [2] b9 e1 [2] 84 }

  condition:
    any of them
}