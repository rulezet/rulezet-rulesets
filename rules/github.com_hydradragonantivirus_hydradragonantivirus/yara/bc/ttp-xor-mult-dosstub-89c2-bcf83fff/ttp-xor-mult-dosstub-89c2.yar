rule TTP_XOR_MULT_DOSStub_89c2 {
  strings:
    $key_89c2 = { dd aa [2] a9 b2 [2] ee b0 [2] a9 a1 [2] e7 ad [2] eb a7 [2] fc ac [2] e7 e2 [2] da }

  condition:
    any of them
}