rule TTP_XOR_MULT_DOSStub_8d70 {
  strings:
    $key_8d70 = { d9 18 [2] ad 00 [2] ea 02 [2] ad 13 [2] e3 1f [2] ef 15 [2] f8 1e [2] e3 50 [2] de }

  condition:
    any of them
}