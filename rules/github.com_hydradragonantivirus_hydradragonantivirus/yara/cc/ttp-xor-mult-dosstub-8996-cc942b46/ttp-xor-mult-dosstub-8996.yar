rule TTP_XOR_MULT_DOSStub_8996 {
  strings:
    $key_8996 = { dd fe [2] a9 e6 [2] ee e4 [2] a9 f5 [2] e7 f9 [2] eb f3 [2] fc f8 [2] e7 b6 [2] da }

  condition:
    any of them
}