rule TTP_XOR_MULT_DOSStub_89c1 {
  strings:
    $key_89c1 = { dd a9 [2] a9 b1 [2] ee b3 [2] a9 a2 [2] e7 ae [2] eb a4 [2] fc af [2] e7 e1 [2] da }

  condition:
    any of them
}