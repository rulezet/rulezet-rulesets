rule TTP_XOR_MULT_DOSStub_d6b7 {
  strings:
    $key_d6b7 = { 82 df [2] f6 c7 [2] b1 c5 [2] f6 d4 [2] b8 d8 [2] b4 d2 [2] a3 d9 [2] b8 97 [2] 85 }

  condition:
    any of them
}