rule TTP_XOR_MULT_DOSStub_81b7 {
  strings:
    $key_81b7 = { d5 df [2] a1 c7 [2] e6 c5 [2] a1 d4 [2] ef d8 [2] e3 d2 [2] f4 d9 [2] ef 97 [2] d2 }

  condition:
    any of them
}