rule TTP_XOR_MULT_DOSStub_8d4b {
  strings:
    $key_8d4b = { d9 23 [2] ad 3b [2] ea 39 [2] ad 28 [2] e3 24 [2] ef 2e [2] f8 25 [2] e3 6b [2] de }

  condition:
    any of them
}