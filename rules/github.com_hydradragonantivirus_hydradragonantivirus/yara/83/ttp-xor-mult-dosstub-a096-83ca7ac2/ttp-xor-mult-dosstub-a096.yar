rule TTP_XOR_MULT_DOSStub_a096 {
  strings:
    $key_a096 = { f4 fe [2] 80 e6 [2] c7 e4 [2] 80 f5 [2] ce f9 [2] c2 f3 [2] d5 f8 [2] ce b6 [2] f3 }

  condition:
    any of them
}