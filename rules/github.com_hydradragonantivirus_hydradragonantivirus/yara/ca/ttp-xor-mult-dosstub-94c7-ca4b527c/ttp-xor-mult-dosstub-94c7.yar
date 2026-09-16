rule TTP_XOR_MULT_DOSStub_94c7 {
  strings:
    $key_94c7 = { c0 af [2] b4 b7 [2] f3 b5 [2] b4 a4 [2] fa a8 [2] f6 a2 [2] e1 a9 [2] fa e7 [2] c7 }

  condition:
    any of them
}