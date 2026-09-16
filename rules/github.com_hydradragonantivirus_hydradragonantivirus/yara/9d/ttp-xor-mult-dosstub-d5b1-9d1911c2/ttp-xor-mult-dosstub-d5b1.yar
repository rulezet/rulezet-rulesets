rule TTP_XOR_MULT_DOSStub_d5b1 {
  strings:
    $key_d5b1 = { 81 d9 [2] f5 c1 [2] b2 c3 [2] f5 d2 [2] bb de [2] b7 d4 [2] a0 df [2] bb 91 [2] 86 }

  condition:
    any of them
}