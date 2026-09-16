rule TTP_XOR_MULT_DOSStub_8d1c {
  strings:
    $key_8d1c = { d9 74 [2] ad 6c [2] ea 6e [2] ad 7f [2] e3 73 [2] ef 79 [2] f8 72 [2] e3 3c [2] de }

  condition:
    any of them
}