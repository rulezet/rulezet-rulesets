rule TTP_XOR_MULT_DOSStub_8df1 {
  strings:
    $key_8df1 = { d9 99 [2] ad 81 [2] ea 83 [2] ad 92 [2] e3 9e [2] ef 94 [2] f8 9f [2] e3 d1 [2] de }

  condition:
    any of them
}