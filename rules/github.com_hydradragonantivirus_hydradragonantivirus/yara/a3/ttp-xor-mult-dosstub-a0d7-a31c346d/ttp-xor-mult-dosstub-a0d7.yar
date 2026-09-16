rule TTP_XOR_MULT_DOSStub_a0d7 {
  strings:
    $key_a0d7 = { f4 bf [2] 80 a7 [2] c7 a5 [2] 80 b4 [2] ce b8 [2] c2 b2 [2] d5 b9 [2] ce f7 [2] f3 }

  condition:
    any of them
}