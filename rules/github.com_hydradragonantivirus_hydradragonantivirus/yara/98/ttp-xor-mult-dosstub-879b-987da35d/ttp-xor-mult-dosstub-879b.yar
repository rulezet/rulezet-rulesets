rule TTP_XOR_MULT_DOSStub_879b {
  strings:
    $key_879b = { d3 f3 [2] a7 eb [2] e0 e9 [2] a7 f8 [2] e9 f4 [2] e5 fe [2] f2 f5 [2] e9 bb [2] d4 }

  condition:
    any of them
}