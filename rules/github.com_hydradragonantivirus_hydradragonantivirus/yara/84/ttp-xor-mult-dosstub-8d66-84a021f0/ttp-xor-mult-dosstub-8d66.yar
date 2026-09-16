rule TTP_XOR_MULT_DOSStub_8d66 {
  strings:
    $key_8d66 = { d9 0e [2] ad 16 [2] ea 14 [2] ad 05 [2] e3 09 [2] ef 03 [2] f8 08 [2] e3 46 [2] de }

  condition:
    any of them
}