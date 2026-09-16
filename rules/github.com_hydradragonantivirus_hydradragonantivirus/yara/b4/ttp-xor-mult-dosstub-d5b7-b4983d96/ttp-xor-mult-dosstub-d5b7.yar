rule TTP_XOR_MULT_DOSStub_d5b7 {
  strings:
    $key_d5b7 = { 81 df [2] f5 c7 [2] b2 c5 [2] f5 d4 [2] bb d8 [2] b7 d2 [2] a0 d9 [2] bb 97 [2] 86 }

  condition:
    any of them
}