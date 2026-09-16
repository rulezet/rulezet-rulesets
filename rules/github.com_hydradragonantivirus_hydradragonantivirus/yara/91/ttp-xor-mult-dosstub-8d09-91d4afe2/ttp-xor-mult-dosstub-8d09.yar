rule TTP_XOR_MULT_DOSStub_8d09 {
  strings:
    $key_8d09 = { d9 61 [2] ad 79 [2] ea 7b [2] ad 6a [2] e3 66 [2] ef 6c [2] f8 67 [2] e3 29 [2] de }

  condition:
    any of them
}