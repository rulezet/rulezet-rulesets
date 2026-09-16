rule TTP_XOR_MULT_DOSStub_84b7 {
  strings:
    $key_84b7 = { d0 df [2] a4 c7 [2] e3 c5 [2] a4 d4 [2] ea d8 [2] e6 d2 [2] f1 d9 [2] ea 97 [2] d7 }

  condition:
    any of them
}