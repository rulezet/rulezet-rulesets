rule TTP_XOR_MULT_DOSStub_a0d6 {
  strings:
    $key_a0d6 = { f4 be [2] 80 a6 [2] c7 a4 [2] 80 b5 [2] ce b9 [2] c2 b3 [2] d5 b8 [2] ce f6 [2] f3 }

  condition:
    any of them
}