rule TTP_XOR_MULT_DOSStub_8d30 {
  strings:
    $key_8d30 = { d9 58 [2] ad 40 [2] ea 42 [2] ad 53 [2] e3 5f [2] ef 55 [2] f8 5e [2] e3 10 [2] de }

  condition:
    any of them
}