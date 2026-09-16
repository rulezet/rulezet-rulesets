rule TTP_XOR_MULT_DOSStub_8df6 {
  strings:
    $key_8df6 = { d9 9e [2] ad 86 [2] ea 84 [2] ad 95 [2] e3 99 [2] ef 93 [2] f8 98 [2] e3 d6 [2] de }

  condition:
    any of them
}