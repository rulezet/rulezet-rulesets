rule TTP_XOR_MULT_DOSStub_8d01 {
  strings:
    $key_8d01 = { d9 69 [2] ad 71 [2] ea 73 [2] ad 62 [2] e3 6e [2] ef 64 [2] f8 6f [2] e3 21 [2] de }

  condition:
    any of them
}