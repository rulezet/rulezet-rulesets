rule TTP_XOR_MULT_DOSStub_a4d1 {
  strings:
    $key_a4d1 = { f0 b9 [2] 84 a1 [2] c3 a3 [2] 84 b2 [2] ca be [2] c6 b4 [2] d1 bf [2] ca f1 [2] f7 }

  condition:
    any of them
}