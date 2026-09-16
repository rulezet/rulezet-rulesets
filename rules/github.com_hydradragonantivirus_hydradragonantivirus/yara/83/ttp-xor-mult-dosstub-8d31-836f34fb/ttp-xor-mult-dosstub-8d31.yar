rule TTP_XOR_MULT_DOSStub_8d31 {
  strings:
    $key_8d31 = { d9 59 [2] ad 41 [2] ea 43 [2] ad 52 [2] e3 5e [2] ef 54 [2] f8 5f [2] e3 11 [2] de }

  condition:
    any of them
}