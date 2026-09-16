rule TTP_XOR_MULT_DOSStub_8d16 {
  strings:
    $key_8d16 = { d9 7e [2] ad 66 [2] ea 64 [2] ad 75 [2] e3 79 [2] ef 73 [2] f8 78 [2] e3 36 [2] de }

  condition:
    any of them
}