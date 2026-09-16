rule TTP_XOR_MULT_DOSStub_84b1 {
  strings:
    $key_84b1 = { d0 d9 [2] a4 c1 [2] e3 c3 [2] a4 d2 [2] ea de [2] e6 d4 [2] f1 df [2] ea 91 [2] d7 }

  condition:
    any of them
}