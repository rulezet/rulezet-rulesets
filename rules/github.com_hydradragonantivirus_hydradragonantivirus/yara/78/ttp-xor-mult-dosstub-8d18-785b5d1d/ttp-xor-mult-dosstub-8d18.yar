rule TTP_XOR_MULT_DOSStub_8d18 {
  strings:
    $key_8d18 = { d9 70 [2] ad 68 [2] ea 6a [2] ad 7b [2] e3 77 [2] ef 7d [2] f8 76 [2] e3 38 [2] de }

  condition:
    any of them
}