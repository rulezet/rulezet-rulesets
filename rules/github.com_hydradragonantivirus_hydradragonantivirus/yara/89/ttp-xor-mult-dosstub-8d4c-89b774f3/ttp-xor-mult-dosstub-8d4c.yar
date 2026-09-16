rule TTP_XOR_MULT_DOSStub_8d4c {
  strings:
    $key_8d4c = { d9 24 [2] ad 3c [2] ea 3e [2] ad 2f [2] e3 23 [2] ef 29 [2] f8 22 [2] e3 6c [2] de }

  condition:
    any of them
}