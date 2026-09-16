rule TTP_XOR_MULT_DOSStub_89c4 {
  strings:
    $key_89c4 = { dd ac [2] a9 b4 [2] ee b6 [2] a9 a7 [2] e7 ab [2] eb a1 [2] fc aa [2] e7 e4 [2] da }

  condition:
    any of them
}