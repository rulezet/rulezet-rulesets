rule TTP_XOR_MULT_DOSStub_94c6 {
  strings:
    $key_94c6 = { c0 ae [2] b4 b6 [2] f3 b4 [2] b4 a5 [2] fa a9 [2] f6 a3 [2] e1 a8 [2] fa e6 [2] c7 }

  condition:
    any of them
}