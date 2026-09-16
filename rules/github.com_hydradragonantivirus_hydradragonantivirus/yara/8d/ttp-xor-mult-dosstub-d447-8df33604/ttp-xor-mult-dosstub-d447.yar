rule TTP_XOR_MULT_DOSStub_d447 {
  strings:
    $key_d447 = { 80 2f [2] f4 37 [2] b3 35 [2] f4 24 [2] ba 28 [2] b6 22 [2] a1 29 [2] ba 67 [2] 87 }

  condition:
    any of them
}