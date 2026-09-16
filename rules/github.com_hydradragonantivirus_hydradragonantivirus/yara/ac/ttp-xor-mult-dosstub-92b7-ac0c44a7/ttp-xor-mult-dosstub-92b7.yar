rule TTP_XOR_MULT_DOSStub_92b7 {
  strings:
    $key_92b7 = { c6 df [2] b2 c7 [2] f5 c5 [2] b2 d4 [2] fc d8 [2] f0 d2 [2] e7 d9 [2] fc 97 [2] c1 }

  condition:
    any of them
}