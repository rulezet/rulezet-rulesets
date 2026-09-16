rule TTP_XOR_MULT_DOSStub_a4d7 {
  strings:
    $key_a4d7 = { f0 bf [2] 84 a7 [2] c3 a5 [2] 84 b4 [2] ca b8 [2] c6 b2 [2] d1 b9 [2] ca f7 [2] f7 }

  condition:
    any of them
}