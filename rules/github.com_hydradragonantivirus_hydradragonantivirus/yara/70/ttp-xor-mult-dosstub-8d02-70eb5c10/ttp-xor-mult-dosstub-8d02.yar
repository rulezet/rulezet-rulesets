rule TTP_XOR_MULT_DOSStub_8d02 {
  strings:
    $key_8d02 = { d9 6a [2] ad 72 [2] ea 70 [2] ad 61 [2] e3 6d [2] ef 67 [2] f8 6c [2] e3 22 [2] de }

  condition:
    any of them
}