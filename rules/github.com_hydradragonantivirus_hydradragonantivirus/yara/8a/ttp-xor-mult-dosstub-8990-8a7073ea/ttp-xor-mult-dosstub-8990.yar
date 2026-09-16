rule TTP_XOR_MULT_DOSStub_8990 {
  strings:
    $key_8990 = { dd f8 [2] a9 e0 [2] ee e2 [2] a9 f3 [2] e7 ff [2] eb f5 [2] fc fe [2] e7 b0 [2] da }

  condition:
    any of them
}