rule TTP_XOR_MULT_DOSStub_97b1 {
  strings:
    $key_97b1 = { c3 d9 [2] b7 c1 [2] f0 c3 [2] b7 d2 [2] f9 de [2] f5 d4 [2] e2 df [2] f9 91 [2] c4 }

  condition:
    any of them
}