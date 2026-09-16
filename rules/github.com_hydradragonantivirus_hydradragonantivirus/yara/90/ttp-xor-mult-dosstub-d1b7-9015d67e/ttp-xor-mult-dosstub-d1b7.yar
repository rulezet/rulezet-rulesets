rule TTP_XOR_MULT_DOSStub_d1b7 {
  strings:
    $key_d1b7 = { 85 df [2] f1 c7 [2] b6 c5 [2] f1 d4 [2] bf d8 [2] b3 d2 [2] a4 d9 [2] bf 97 [2] 82 }

  condition:
    any of them
}