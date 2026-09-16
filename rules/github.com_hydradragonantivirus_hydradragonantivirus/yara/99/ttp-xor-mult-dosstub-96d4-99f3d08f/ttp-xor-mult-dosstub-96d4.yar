rule TTP_XOR_MULT_DOSStub_96d4 {
  strings:
    $key_96d4 = { c2 bc [2] b6 a4 [2] f1 a6 [2] b6 b7 [2] f8 bb [2] f4 b1 [2] e3 ba [2] f8 f4 [2] c5 }

  condition:
    any of them
}