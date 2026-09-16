rule TTP_XOR_MULT_DOSStub_8cb0 {
  strings:
    $key_8cb0 = { d8 d8 [2] ac c0 [2] eb c2 [2] ac d3 [2] e2 df [2] ee d5 [2] f9 de [2] e2 90 [2] df }

  condition:
    any of them
}