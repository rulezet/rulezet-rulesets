rule TTP_XOR_MULT_DOSStub_95b1 {
  strings:
    $key_95b1 = { c1 d9 [2] b5 c1 [2] f2 c3 [2] b5 d2 [2] fb de [2] f7 d4 [2] e0 df [2] fb 91 [2] c6 }

  condition:
    any of them
}