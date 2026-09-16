rule TTP_XOR_MULT_DOSStub_84c7 {
  strings:
    $key_84c7 = { d0 af [2] a4 b7 [2] e3 b5 [2] a4 a4 [2] ea a8 [2] e6 a2 [2] f1 a9 [2] ea e7 [2] d7 }

  condition:
    any of them
}