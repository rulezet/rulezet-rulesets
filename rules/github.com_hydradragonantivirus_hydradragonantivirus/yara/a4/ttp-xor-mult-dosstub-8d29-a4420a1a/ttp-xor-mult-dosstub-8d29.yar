rule TTP_XOR_MULT_DOSStub_8d29 {
  strings:
    $key_8d29 = { d9 41 [2] ad 59 [2] ea 5b [2] ad 4a [2] e3 46 [2] ef 4c [2] f8 47 [2] e3 09 [2] de }

  condition:
    any of them
}