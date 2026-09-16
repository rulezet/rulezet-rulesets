rule TTP_XOR_MULT_DOSStub_8db1 {
  strings:
    $key_8db1 = { d9 d9 [2] ad c1 [2] ea c3 [2] ad d2 [2] e3 de [2] ef d4 [2] f8 df [2] e3 91 [2] de }

  condition:
    any of them
}