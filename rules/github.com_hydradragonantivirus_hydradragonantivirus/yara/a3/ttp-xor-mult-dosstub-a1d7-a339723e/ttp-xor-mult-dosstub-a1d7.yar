rule TTP_XOR_MULT_DOSStub_a1d7 {
  strings:
    $key_a1d7 = { f5 bf [2] 81 a7 [2] c6 a5 [2] 81 b4 [2] cf b8 [2] c3 b2 [2] d4 b9 [2] cf f7 [2] f2 }

  condition:
    any of them
}