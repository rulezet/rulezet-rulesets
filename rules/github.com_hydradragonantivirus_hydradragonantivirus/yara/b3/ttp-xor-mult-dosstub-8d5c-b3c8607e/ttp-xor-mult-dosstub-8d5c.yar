rule TTP_XOR_MULT_DOSStub_8d5c {
  strings:
    $key_8d5c = { d9 34 [2] ad 2c [2] ea 2e [2] ad 3f [2] e3 33 [2] ef 39 [2] f8 32 [2] e3 7c [2] de }

  condition:
    any of them
}