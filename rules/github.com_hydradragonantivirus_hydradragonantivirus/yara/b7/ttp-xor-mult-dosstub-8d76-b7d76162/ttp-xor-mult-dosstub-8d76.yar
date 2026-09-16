rule TTP_XOR_MULT_DOSStub_8d76 {
  strings:
    $key_8d76 = { d9 1e [2] ad 06 [2] ea 04 [2] ad 15 [2] e3 19 [2] ef 13 [2] f8 18 [2] e3 56 [2] de }

  condition:
    any of them
}