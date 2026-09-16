rule TTP_XOR_MULT_DOSStub_d456 {
  strings:
    $key_d456 = { 80 3e [2] f4 26 [2] b3 24 [2] f4 35 [2] ba 39 [2] b6 33 [2] a1 38 [2] ba 76 [2] 87 }

  condition:
    any of them
}