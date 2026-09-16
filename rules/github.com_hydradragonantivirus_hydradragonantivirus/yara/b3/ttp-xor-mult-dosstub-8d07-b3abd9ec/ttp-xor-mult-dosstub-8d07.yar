rule TTP_XOR_MULT_DOSStub_8d07 {
  strings:
    $key_8d07 = { d9 6f [2] ad 77 [2] ea 75 [2] ad 64 [2] e3 68 [2] ef 62 [2] f8 69 [2] e3 27 [2] de }

  condition:
    any of them
}