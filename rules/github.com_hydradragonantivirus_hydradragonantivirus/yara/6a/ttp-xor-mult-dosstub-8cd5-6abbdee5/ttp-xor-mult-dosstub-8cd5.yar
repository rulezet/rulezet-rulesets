rule TTP_XOR_MULT_DOSStub_8cd5 {
  strings:
    $key_8cd5 = { d8 bd [2] ac a5 [2] eb a7 [2] ac b6 [2] e2 ba [2] ee b0 [2] f9 bb [2] e2 f5 [2] df }

  condition:
    any of them
}