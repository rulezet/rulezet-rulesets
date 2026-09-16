rule TTP_XOR_MULT_DOSStub_8d41 {
  strings:
    $key_8d41 = { d9 29 [2] ad 31 [2] ea 33 [2] ad 22 [2] e3 2e [2] ef 24 [2] f8 2f [2] e3 61 [2] de }

  condition:
    any of them
}