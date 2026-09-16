rule TTP_XOR_MULT_DOSStub_d4c6 {
  strings:
    $key_d4c6 = { 80 ae [2] f4 b6 [2] b3 b4 [2] f4 a5 [2] ba a9 [2] b6 a3 [2] a1 a8 [2] ba e6 [2] 87 }

  condition:
    any of them
}