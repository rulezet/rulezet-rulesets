rule TTP_XOR_MULT_DOSStub_86b7 {
  strings:
    $key_86b7 = { d2 df [2] a6 c7 [2] e1 c5 [2] a6 d4 [2] e8 d8 [2] e4 d2 [2] f3 d9 [2] e8 97 [2] d5 }

  condition:
    any of them
}