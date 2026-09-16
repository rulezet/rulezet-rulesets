rule TTP_XOR_MULT_DOSStub_8090 {
  strings:
    $key_8090 = { d4 f8 [2] a0 e0 [2] e7 e2 [2] a0 f3 [2] ee ff [2] e2 f5 [2] f5 fe [2] ee b0 [2] d3 }

  condition:
    any of them
}