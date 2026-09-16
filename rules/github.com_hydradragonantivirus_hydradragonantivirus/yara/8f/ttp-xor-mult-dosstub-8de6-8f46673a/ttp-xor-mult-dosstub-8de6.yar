rule TTP_XOR_MULT_DOSStub_8de6 {
  strings:
    $key_8de6 = { d9 8e [2] ad 96 [2] ea 94 [2] ad 85 [2] e3 89 [2] ef 83 [2] f8 88 [2] e3 c6 [2] de }

  condition:
    any of them
}