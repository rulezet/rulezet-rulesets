rule TTP_XOR_MULT_DOSStub_96b7 {
  strings:
    $key_96b7 = { c2 df [2] b6 c7 [2] f1 c5 [2] b6 d4 [2] f8 d8 [2] f4 d2 [2] e3 d9 [2] f8 97 [2] c5 }

  condition:
    any of them
}