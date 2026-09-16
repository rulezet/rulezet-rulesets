rule TTP_XOR_MULT_DOSStub_a69b {
  strings:
    $key_a69b = { f2 f3 [2] 86 eb [2] c1 e9 [2] 86 f8 [2] c8 f4 [2] c4 fe [2] d3 f5 [2] c8 bb [2] f5 }

  condition:
    any of them
}