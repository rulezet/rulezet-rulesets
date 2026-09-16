rule TTP_XOR_MULT_DOSStub_8098 {
  strings:
    $key_8098 = { d4 f0 [2] a0 e8 [2] e7 ea [2] a0 fb [2] ee f7 [2] e2 fd [2] f5 f6 [2] ee b8 [2] d3 }

  condition:
    any of them
}