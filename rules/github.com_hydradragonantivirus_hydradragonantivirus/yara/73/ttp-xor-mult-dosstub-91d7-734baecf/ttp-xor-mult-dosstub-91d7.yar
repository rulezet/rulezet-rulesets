rule TTP_XOR_MULT_DOSStub_91d7 {
  strings:
    $key_91d7 = { c5 bf [2] b1 a7 [2] f6 a5 [2] b1 b4 [2] ff b8 [2] f3 b2 [2] e4 b9 [2] ff f7 [2] c2 }

  condition:
    any of them
}