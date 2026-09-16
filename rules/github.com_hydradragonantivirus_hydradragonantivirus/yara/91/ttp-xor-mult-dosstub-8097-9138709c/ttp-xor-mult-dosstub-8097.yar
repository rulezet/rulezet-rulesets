rule TTP_XOR_MULT_DOSStub_8097 {
  strings:
    $key_8097 = { d4 ff [2] a0 e7 [2] e7 e5 [2] a0 f4 [2] ee f8 [2] e2 f2 [2] f5 f9 [2] ee b7 [2] d3 }

  condition:
    any of them
}