rule TTP_XOR_MULT_DOSStub_a2d7 {
  strings:
    $key_a2d7 = { f6 bf [2] 82 a7 [2] c5 a5 [2] 82 b4 [2] cc b8 [2] c0 b2 [2] d7 b9 [2] cc f7 [2] f1 }

  condition:
    any of them
}