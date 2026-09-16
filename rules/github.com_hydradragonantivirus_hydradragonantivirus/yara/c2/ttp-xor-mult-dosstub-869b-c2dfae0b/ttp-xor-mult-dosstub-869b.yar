rule TTP_XOR_MULT_DOSStub_869b {
  strings:
    $key_869b = { d2 f3 [2] a6 eb [2] e1 e9 [2] a6 f8 [2] e8 f4 [2] e4 fe [2] f3 f5 [2] e8 bb [2] d5 }

  condition:
    any of them
}