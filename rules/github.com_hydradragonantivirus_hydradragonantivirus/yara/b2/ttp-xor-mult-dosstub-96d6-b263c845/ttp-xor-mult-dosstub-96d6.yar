rule TTP_XOR_MULT_DOSStub_96d6 {
  strings:
    $key_96d6 = { c2 be [2] b6 a6 [2] f1 a4 [2] b6 b5 [2] f8 b9 [2] f4 b3 [2] e3 b8 [2] f8 f6 [2] c5 }

  condition:
    any of them
}