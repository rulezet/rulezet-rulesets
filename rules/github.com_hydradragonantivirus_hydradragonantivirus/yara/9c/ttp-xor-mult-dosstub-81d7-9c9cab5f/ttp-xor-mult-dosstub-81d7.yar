rule TTP_XOR_MULT_DOSStub_81d7 {
  strings:
    $key_81d7 = { d5 bf [2] a1 a7 [2] e6 a5 [2] a1 b4 [2] ef b8 [2] e3 b2 [2] f4 b9 [2] ef f7 [2] d2 }

  condition:
    any of them
}