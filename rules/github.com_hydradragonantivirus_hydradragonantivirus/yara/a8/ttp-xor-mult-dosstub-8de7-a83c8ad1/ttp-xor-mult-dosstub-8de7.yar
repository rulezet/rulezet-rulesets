rule TTP_XOR_MULT_DOSStub_8de7 {
  strings:
    $key_8de7 = { d9 8f [2] ad 97 [2] ea 95 [2] ad 84 [2] e3 88 [2] ef 82 [2] f8 89 [2] e3 c7 [2] de }

  condition:
    any of them
}