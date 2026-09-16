rule TTP_XOR_MULT_DOSStub_a091 {
  strings:
    $key_a091 = { f4 f9 [2] 80 e1 [2] c7 e3 [2] 80 f2 [2] ce fe [2] c2 f4 [2] d5 ff [2] ce b1 [2] f3 }

  condition:
    any of them
}