rule TTP_XOR_MULT_DOSStub_89c5 {
  strings:
    $key_89c5 = { dd ad [2] a9 b5 [2] ee b7 [2] a9 a6 [2] e7 aa [2] eb a0 [2] fc ab [2] e7 e5 [2] da }

  condition:
    any of them
}