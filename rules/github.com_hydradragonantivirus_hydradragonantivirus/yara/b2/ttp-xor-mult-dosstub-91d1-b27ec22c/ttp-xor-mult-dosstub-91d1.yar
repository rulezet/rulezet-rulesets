rule TTP_XOR_MULT_DOSStub_91d1 {
  strings:
    $key_91d1 = { c5 b9 [2] b1 a1 [2] f6 a3 [2] b1 b2 [2] ff be [2] f3 b4 [2] e4 bf [2] ff f1 [2] c2 }

  condition:
    any of them
}