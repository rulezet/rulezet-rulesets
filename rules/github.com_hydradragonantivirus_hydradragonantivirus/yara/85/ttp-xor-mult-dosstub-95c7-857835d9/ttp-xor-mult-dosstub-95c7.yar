rule TTP_XOR_MULT_DOSStub_95c7 {
  strings:
    $key_95c7 = { c1 af [2] b5 b7 [2] f2 b5 [2] b5 a4 [2] fb a8 [2] f7 a2 [2] e0 a9 [2] fb e7 [2] c6 }

  condition:
    any of them
}