rule TTP_XOR_MULT_DOSStub_96d1 {
  strings:
    $key_96d1 = { c2 b9 [2] b6 a1 [2] f1 a3 [2] b6 b2 [2] f8 be [2] f4 b4 [2] e3 bf [2] f8 f1 [2] c5 }

  condition:
    any of them
}