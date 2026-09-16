rule TTP_XOR_MULT_DOSStub_8db0 {
  strings:
    $key_8db0 = { d9 d8 [2] ad c0 [2] ea c2 [2] ad d3 [2] e3 df [2] ef d5 [2] f8 de [2] e3 90 [2] de }

  condition:
    any of them
}