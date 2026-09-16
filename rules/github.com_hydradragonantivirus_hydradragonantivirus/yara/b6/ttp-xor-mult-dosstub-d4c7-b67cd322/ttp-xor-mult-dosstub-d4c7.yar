rule TTP_XOR_MULT_DOSStub_d4c7 {
  strings:
    $key_d4c7 = { 80 af [2] f4 b7 [2] b3 b5 [2] f4 a4 [2] ba a8 [2] b6 a2 [2] a1 a9 [2] ba e7 [2] 87 }

  condition:
    any of them
}