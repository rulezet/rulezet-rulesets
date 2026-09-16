rule TTP_XOR_MULT_DOSStub_83b7 {
  strings:
    $key_83b7 = { d7 df [2] a3 c7 [2] e4 c5 [2] a3 d4 [2] ed d8 [2] e1 d2 [2] f6 d9 [2] ed 97 [2] d0 }

  condition:
    any of them
}