rule TTP_XOR_MULT_DOSStub_8d60 {
  strings:
    $key_8d60 = { d9 08 [2] ad 10 [2] ea 12 [2] ad 03 [2] e3 0f [2] ef 05 [2] f8 0e [2] e3 40 [2] de }

  condition:
    any of them
}