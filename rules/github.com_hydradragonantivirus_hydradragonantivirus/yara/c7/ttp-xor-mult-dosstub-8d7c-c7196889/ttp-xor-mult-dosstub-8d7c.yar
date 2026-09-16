rule TTP_XOR_MULT_DOSStub_8d7c {
  strings:
    $key_8d7c = { d9 14 [2] ad 0c [2] ea 0e [2] ad 1f [2] e3 13 [2] ef 19 [2] f8 12 [2] e3 5c [2] de }

  condition:
    any of them
}