rule TTP_XOR_MULT_DOSStub_92d7 {
  strings:
    $key_92d7 = { c6 bf [2] b2 a7 [2] f5 a5 [2] b2 b4 [2] fc b8 [2] f0 b2 [2] e7 b9 [2] fc f7 [2] c1 }

  condition:
    any of them
}