rule TTP_XOR_MULT_DOSStub_80d6 {
  strings:
    $key_80d6 = { d4 be [2] a0 a6 [2] e7 a4 [2] a0 b5 [2] ee b9 [2] e2 b3 [2] f5 b8 [2] ee f6 [2] d3 }

  condition:
    any of them
}