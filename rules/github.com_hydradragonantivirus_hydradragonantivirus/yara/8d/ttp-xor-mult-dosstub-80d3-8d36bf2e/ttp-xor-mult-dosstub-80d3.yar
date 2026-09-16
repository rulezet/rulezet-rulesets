rule TTP_XOR_MULT_DOSStub_80d3 {
  strings:
    $key_80d3 = { d4 bb [2] a0 a3 [2] e7 a1 [2] a0 b0 [2] ee bc [2] e2 b6 [2] f5 bd [2] ee f3 [2] d3 }

  condition:
    any of them
}