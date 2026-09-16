rule TTP_XOR_MULT_DOSStub_8df2 {
  strings:
    $key_8df2 = { d9 9a [2] ad 82 [2] ea 80 [2] ad 91 [2] e3 9d [2] ef 97 [2] f8 9c [2] e3 d2 [2] de }

  condition:
    any of them
}