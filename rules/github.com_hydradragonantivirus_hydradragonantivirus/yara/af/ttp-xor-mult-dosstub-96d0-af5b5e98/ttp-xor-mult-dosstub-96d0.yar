rule TTP_XOR_MULT_DOSStub_96d0 {
  strings:
    $key_96d0 = { c2 b8 [2] b6 a0 [2] f1 a2 [2] b6 b3 [2] f8 bf [2] f4 b5 [2] e3 be [2] f8 f0 [2] c5 }

  condition:
    any of them
}