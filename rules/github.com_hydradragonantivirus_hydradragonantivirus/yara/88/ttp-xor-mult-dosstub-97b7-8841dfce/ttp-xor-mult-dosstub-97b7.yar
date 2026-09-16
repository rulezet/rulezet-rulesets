rule TTP_XOR_MULT_DOSStub_97b7 {
  strings:
    $key_97b7 = { c3 df [2] b7 c7 [2] f0 c5 [2] b7 d4 [2] f9 d8 [2] f5 d2 [2] e2 d9 [2] f9 97 [2] c4 }

  condition:
    any of them
}