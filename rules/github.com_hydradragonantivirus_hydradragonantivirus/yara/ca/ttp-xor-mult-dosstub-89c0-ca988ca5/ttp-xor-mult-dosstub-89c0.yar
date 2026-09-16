rule TTP_XOR_MULT_DOSStub_89c0 {
  strings:
    $key_89c0 = { dd a8 [2] a9 b0 [2] ee b2 [2] a9 a3 [2] e7 af [2] eb a5 [2] fc ae [2] e7 e0 [2] da }

  condition:
    any of them
}