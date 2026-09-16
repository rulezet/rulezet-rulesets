rule TTP_XOR_MULT_DOSStub_a696 {
  strings:
    $key_a696 = { f2 fe [2] 86 e6 [2] c1 e4 [2] 86 f5 [2] c8 f9 [2] c4 f3 [2] d3 f8 [2] c8 b6 [2] f5 }

  condition:
    any of them
}