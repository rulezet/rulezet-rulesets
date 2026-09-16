rule TTP_XOR_MULT_DOSStub_80d0 {
  strings:
    $key_80d0 = { d4 b8 [2] a0 a0 [2] e7 a2 [2] a0 b3 [2] ee bf [2] e2 b5 [2] f5 be [2] ee f0 [2] d3 }

  condition:
    any of them
}