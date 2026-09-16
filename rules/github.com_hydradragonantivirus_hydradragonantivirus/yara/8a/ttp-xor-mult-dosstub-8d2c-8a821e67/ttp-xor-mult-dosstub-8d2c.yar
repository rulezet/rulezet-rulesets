rule TTP_XOR_MULT_DOSStub_8d2c {
  strings:
    $key_8d2c = { d9 44 [2] ad 5c [2] ea 5e [2] ad 4f [2] e3 43 [2] ef 49 [2] f8 42 [2] e3 0c [2] de }

  condition:
    any of them
}