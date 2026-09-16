rule TTP_XOR_MULT_DOSStub_a2d1 {
  strings:
    $key_a2d1 = { f6 b9 [2] 82 a1 [2] c5 a3 [2] 82 b2 [2] cc be [2] c0 b4 [2] d7 bf [2] cc f1 [2] f1 }

  condition:
    any of them
}