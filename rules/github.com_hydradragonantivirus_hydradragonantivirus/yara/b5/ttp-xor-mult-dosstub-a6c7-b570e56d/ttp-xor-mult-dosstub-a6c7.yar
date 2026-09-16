rule TTP_XOR_MULT_DOSStub_a6c7 {
  strings:
    $key_a6c7 = { f2 af [2] 86 b7 [2] c1 b5 [2] 86 a4 [2] c8 a8 [2] c4 a2 [2] d3 a9 [2] c8 e7 [2] f5 }

  condition:
    any of them
}