rule TTP_XOR_MULT_DOSStub_8093 {
  strings:
    $key_8093 = { d4 fb [2] a0 e3 [2] e7 e1 [2] a0 f0 [2] ee fc [2] e2 f6 [2] f5 fd [2] ee b3 [2] d3 }

  condition:
    any of them
}