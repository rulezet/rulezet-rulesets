rule TTP_XOR_MULT_DOSStub_94c0 {
  strings:
    $key_94c0 = { c0 a8 [2] b4 b0 [2] f3 b2 [2] b4 a3 [2] fa af [2] f6 a5 [2] e1 ae [2] fa e0 [2] c7 }

  condition:
    any of them
}