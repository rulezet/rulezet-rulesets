rule TTP_XOR_MULT_DOSStub_a496 {
  strings:
    $key_a496 = { f0 fe [2] 84 e6 [2] c3 e4 [2] 84 f5 [2] ca f9 [2] c6 f3 [2] d1 f8 [2] ca b6 [2] f7 }

  condition:
    any of them
}