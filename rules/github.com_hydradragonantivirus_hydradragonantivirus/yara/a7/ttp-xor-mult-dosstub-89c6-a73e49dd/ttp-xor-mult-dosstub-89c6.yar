rule TTP_XOR_MULT_DOSStub_89c6 {
  strings:
    $key_89c6 = { dd ae [2] a9 b6 [2] ee b4 [2] a9 a5 [2] e7 a9 [2] eb a3 [2] fc a8 [2] e7 e6 [2] da }

  condition:
    any of them
}