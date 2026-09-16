rule TTP_XOR_MULT_DOSStub_8d27 {
  strings:
    $key_8d27 = { d9 4f [2] ad 57 [2] ea 55 [2] ad 44 [2] e3 48 [2] ef 42 [2] f8 49 [2] e3 07 [2] de }

  condition:
    any of them
}