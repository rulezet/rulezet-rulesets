rule TTP_XOR_MULT_DOSStub_a686 {
  strings:
    $key_a686 = { f2 ee [2] 86 f6 [2] c1 f4 [2] 86 e5 [2] c8 e9 [2] c4 e3 [2] d3 e8 [2] c8 a6 [2] f5 }

  condition:
    any of them
}