rule TTP_XOR_MULT_DOSStub_80d4 {
  strings:
    $key_80d4 = { d4 bc [2] a0 a4 [2] e7 a6 [2] a0 b7 [2] ee bb [2] e2 b1 [2] f5 ba [2] ee f4 [2] d3 }

  condition:
    any of them
}