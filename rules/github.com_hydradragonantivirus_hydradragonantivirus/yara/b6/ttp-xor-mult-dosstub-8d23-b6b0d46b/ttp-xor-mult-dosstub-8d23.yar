rule TTP_XOR_MULT_DOSStub_8d23 {
  strings:
    $key_8d23 = { d9 4b [2] ad 53 [2] ea 51 [2] ad 40 [2] e3 4c [2] ef 46 [2] f8 4d [2] e3 03 [2] de }

  condition:
    any of them
}