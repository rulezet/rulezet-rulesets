rule TTP_XOR_MULT_DOSStub_8df8 {
  strings:
    $key_8df8 = { d9 90 [2] ad 88 [2] ea 8a [2] ad 9b [2] e3 97 [2] ef 9d [2] f8 96 [2] e3 d8 [2] de }

  condition:
    any of them
}