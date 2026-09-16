rule TTP_XOR_MULT_DOSStub_8d51 {
  strings:
    $key_8d51 = { d9 39 [2] ad 21 [2] ea 23 [2] ad 32 [2] e3 3e [2] ef 34 [2] f8 3f [2] e3 71 [2] de }

  condition:
    any of them
}