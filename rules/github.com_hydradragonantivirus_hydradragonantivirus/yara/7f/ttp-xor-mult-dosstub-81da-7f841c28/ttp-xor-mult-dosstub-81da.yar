rule TTP_XOR_MULT_DOSStub_81da {
  strings:
    $key_81da = { d5 b2 [2] a1 aa [2] e6 a8 [2] a1 b9 [2] ef b5 [2] e3 bf [2] f4 b4 [2] ef fa [2] d2 }

  condition:
    any of them
}