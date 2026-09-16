rule TTP_XOR_MULT_DOSStub_8cc9 {
  strings:
    $key_8cc9 = { d8 a1 [2] ac b9 [2] eb bb [2] ac aa [2] e2 a6 [2] ee ac [2] f9 a7 [2] e2 e9 [2] df }

  condition:
    any of them
}