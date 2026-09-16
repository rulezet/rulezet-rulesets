rule TTP_XOR_MULT_DOSStub_8d20 {
  strings:
    $key_8d20 = { d9 48 [2] ad 50 [2] ea 52 [2] ad 43 [2] e3 4f [2] ef 45 [2] f8 4e [2] e3 00 [2] de }

  condition:
    any of them
}