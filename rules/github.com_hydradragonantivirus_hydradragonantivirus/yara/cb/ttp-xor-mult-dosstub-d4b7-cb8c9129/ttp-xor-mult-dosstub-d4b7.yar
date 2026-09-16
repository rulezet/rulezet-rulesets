rule TTP_XOR_MULT_DOSStub_d4b7 {
  strings:
    $key_d4b7 = { 80 df [2] f4 c7 [2] b3 c5 [2] f4 d4 [2] ba d8 [2] b6 d2 [2] a1 d9 [2] ba 97 [2] 87 }

  condition:
    any of them
}