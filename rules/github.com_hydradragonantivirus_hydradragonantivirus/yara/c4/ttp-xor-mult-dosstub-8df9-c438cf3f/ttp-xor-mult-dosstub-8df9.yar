rule TTP_XOR_MULT_DOSStub_8df9 {
  strings:
    $key_8df9 = { d9 91 [2] ad 89 [2] ea 8b [2] ad 9a [2] e3 96 [2] ef 9c [2] f8 97 [2] e3 d9 [2] de }

  condition:
    any of them
}