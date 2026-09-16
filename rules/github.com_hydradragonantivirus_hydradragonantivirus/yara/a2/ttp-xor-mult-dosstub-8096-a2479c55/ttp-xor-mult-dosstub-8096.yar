rule TTP_XOR_MULT_DOSStub_8096 {
  strings:
    $key_8096 = { d4 fe [2] a0 e6 [2] e7 e4 [2] a0 f5 [2] ee f9 [2] e2 f3 [2] f5 f8 [2] ee b6 [2] d3 }

  condition:
    any of them
}