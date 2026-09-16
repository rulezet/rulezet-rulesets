rule TTP_XOR_MULT_DOSStub_8d00 {
  strings:
    $key_8d00 = { d9 68 [2] ad 70 [2] ea 72 [2] ad 63 [2] e3 6f [2] ef 65 [2] f8 6e [2] e3 20 [2] de }

  condition:
    any of them
}