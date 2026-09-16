rule TTP_XOR_MULT_DOSStub_8d57 {
  strings:
    $key_8d57 = { d9 3f [2] ad 27 [2] ea 25 [2] ad 34 [2] e3 38 [2] ef 32 [2] f8 39 [2] e3 77 [2] de }

  condition:
    any of them
}